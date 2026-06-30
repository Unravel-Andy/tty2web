package webtty

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"log"
	"strconv"
	"sync"
	"time"

	"github.com/kost/tty2web/utils"
	"github.com/pkg/errors"
)

// WebTTY bridges a PTY slave and its PTY master.
// To support text-based streams and side channel commands such as
// terminal resizing, WebTTY uses an original protocol.
type WebTTY struct {
	// PTY Master, which probably a connection to browser
	masterConn Master
	// PTY Slave
	slave Slave

	windowTitle []byte
	permitWrite bool
	columns     int
	rows        int
	reconnect   int // in seconds
	masterPrefs []byte

	// OTP
	shouldVerifyOTP bool
	lastFailedOTP   time.Time

	bufferSize       int
	writeMutex       sync.Mutex
	auditBuffer      []byte
	oauthCookieValue string
}

const auditMarkerPrefix = "\x1b]777;tty2web-audit="
const auditMarkerSuffix = "\x07"

// Extract the "username" from JWT token
func (wt *WebTTY) getUsernameFromJWT() string {
	if wt.oauthCookieValue == "" {
		return ""
	}
	claims, err := utils.DecodeOauthTokenUnsafe(wt.oauthCookieValue)
	if err != nil {
		log.Printf("Error decoding JWT token unverified: %v", err)
		return ""
	}
	if username, ok := claims["username"].(string); ok {
		return username
	}
	log.Println("Username claim not found or not a string in JWT token.")
	return ""
}

// New creates a new instance of WebTTY.
// masterConn is a connection to the PTY master,
// typically it's a websocket connection to a client.
// slave is a PTY slave such as a local command with a PTY.
func New(masterConn Master, slave Slave, oauthCookieValue string, options ...Option) (*WebTTY, error) {
	wt := &WebTTY{
		masterConn: masterConn,
		slave:      slave,

		permitWrite: false,
		columns:     0,
		rows:        0,

		bufferSize:       102400,
		oauthCookieValue: oauthCookieValue,
	}

	for _, option := range options {
		option(wt)
	}

	return wt, nil
}

// Run starts the main process of the WebTTY.
// This method blocks until the context is canceled.
// Note that the master and slave are left intact even
// after the context is canceled. Closing them is caller's
// responsibility.
// If the connection to one end gets closed, returns ErrSlaveClosed or ErrMasterClosed.
func (wt *WebTTY) Run(ctx context.Context) error {
	err := wt.sendInitializeMessage()
	if err != nil {
		return errors.Wrapf(err, "failed to send initializing message")
	}

	errs := make(chan error, 2)

	go func() {
		errs <- func() error {
			buffer := make([]byte, wt.bufferSize)
			for {
				n, err := wt.slave.Read(buffer)
				if err != nil {
					return ErrSlaveClosed
				}

				// if OTP enabled and not verified - wait for OTP
				for wt.shouldVerifyOTP {
					time.Sleep(1 * time.Second)
				}

				err = wt.handleSlaveReadEvent(buffer[:n])
				if err != nil {
					return err
				}
			}
		}()
	}()

	go func() {
		errs <- func() error {
			buffer := make([]byte, wt.bufferSize)
			for {
				n, err := wt.masterConn.Read(buffer)
				if err != nil {
					return ErrMasterClosed
				}

				err = wt.handleMasterReadEvent(buffer[:n])
				if err != nil {
					return err
				}
			}
		}()
	}()

	select {
	case <-ctx.Done():
		err = ctx.Err()
		wt.shouldVerifyOTP = false
	case err = <-errs:
		wt.shouldVerifyOTP = false
	}

	return err
}

func (wt *WebTTY) sendInitializeMessage() error {
	err := wt.masterWrite(append([]byte{SetWindowTitle}, wt.windowTitle...))
	if err != nil {
		return errors.Wrapf(err, "failed to send window title")
	}

	if wt.reconnect > 0 {
		reconnect, _ := json.Marshal(wt.reconnect)
		err := wt.masterWrite(append([]byte{SetReconnect}, reconnect...))
		if err != nil {
			return errors.Wrapf(err, "failed to set reconnect")
		}
	}

	if wt.masterPrefs != nil {
		err := wt.masterWrite(append([]byte{SetPreferences}, wt.masterPrefs...))
		if err != nil {
			return errors.Wrapf(err, "failed to set preferences")
		}
	}

	// if OTP enabled send OTP prompt
	if wt.shouldVerifyOTP {
		err := wt.sentOTPMessage("please enter the OTP code:")
		if err != nil {
			return errors.Wrapf(err, "failed to send OTP message")
		}
	}

	return nil
}

func (wt *WebTTY) handleSlaveReadEvent(data []byte) error {
	data = wt.filterAuditMarkers(data)
	if len(data) == 0 {
		return nil
	}

	safeMessage := base64.StdEncoding.EncodeToString(data)
	err := wt.masterWrite(append([]byte{Output}, []byte(safeMessage)...))
	if err != nil {
		return errors.Wrapf(err, "failed to send message to master")
	}

	return nil
}

func (wt *WebTTY) filterAuditMarkers(data []byte) []byte {
	data = append(wt.auditBuffer, data...)
	wt.auditBuffer = nil

	var output []byte
	prefix := []byte(auditMarkerPrefix)
	suffix := []byte(auditMarkerSuffix)

	for len(data) > 0 {
		start := bytes.Index(data, prefix)
		if start == -1 {
			keep := auditPrefixOverlap(data, prefix)
			output = append(output, data[:len(data)-keep]...)
			wt.auditBuffer = append(wt.auditBuffer, data[len(data)-keep:]...)
			return output
		}

		output = append(output, data[:start]...)
		data = data[start+len(prefix):]

		end := bytes.Index(data, suffix)
		if end == -1 {
			wt.auditBuffer = append(wt.auditBuffer, prefix...)
			wt.auditBuffer = append(wt.auditBuffer, data...)
			return output
		}

		wt.logAuditCommand(data[:end])
		data = data[end+len(suffix):]
	}

	return output
}

func auditPrefixOverlap(data, prefix []byte) int {
	max := len(prefix) - 1
	if len(data) < max {
		max = len(data)
	}
	for n := max; n > 0; n-- {
		if bytes.Equal(data[len(data)-n:], prefix[:n]) {
			return n
		}
	}
	return 0
}

func (wt *WebTTY) logAuditCommand(encoded []byte) {
	command, err := base64.StdEncoding.DecodeString(string(encoded))
	if err != nil {
		log.Printf("Error decoding audit command: %v", err)
		return
	}
	if len(command) == 0 {
		return
	}

	username := wt.getUsernameFromJWT()
	log.Printf("User %s executed command: %q", username, string(command))
}

func (wt *WebTTY) masterWrite(data []byte) error {
	wt.writeMutex.Lock()
	defer wt.writeMutex.Unlock()

	_, err := wt.masterConn.Write(data)
	if err != nil {
		return errors.Wrapf(err, "failed to write to master")
	}

	return nil
}

func (wt *WebTTY) handleMasterReadEvent(data []byte) error {
	if len(data) == 0 {
		return errors.New("unexpected zero length read from master")
	}

	switch data[0] {
	case Input:
		if !wt.permitWrite {
			return nil
		}

		if len(data) <= 1 {
			return nil
		}

		// if OTP enabled and not verified - wait for OTP
		if wt.shouldVerifyOTP {
			return nil
		}

		_, err := wt.slave.Write(data[1:])
		if err != nil {
			return errors.Wrapf(err, "failed to write received data to slave")
		}

	case Ping:
		err := wt.masterWrite([]byte{Pong})
		if err != nil {
			return errors.Wrapf(err, "failed to return Pong message to master")
		}

	case ResizeTerminal:
		if wt.columns != 0 && wt.rows != 0 {
			break
		}

		if len(data) <= 1 {
			return errors.New("received malformed remote command for terminal resize: empty payload")
		}

		var args argResizeTerminal
		err := json.Unmarshal(data[1:], &args)
		if err != nil {
			return errors.Wrapf(err, "received malformed data for terminal resize")
		}
		rows := wt.rows
		if rows == 0 {
			rows = int(args.Rows)
		}

		columns := wt.columns
		if columns == 0 {
			columns = int(args.Columns)
		}

		wt.slave.ResizeTerminal(columns, rows)
	case OTPInput:
		// brute force OTP input prevention
		bruteForceTimeout := 1500 * time.Millisecond
		if wt.lastFailedOTP.Add(bruteForceTimeout).After(time.Now()) {
			err := wt.sentOTPMessage("\n\rcode incorrect\n\rPlease enter the OTP code:")
			if err != nil {
				return errors.Wrapf(err, "failed to send OTP message")
			}
			lockFor := time.Until(wt.lastFailedOTP.Add(bruteForceTimeout)).Seconds()
			log.Printf("brute force OTP input prevention triggered - waiting %.3f seconds", lockFor)
			return nil
		}
		otp := data[1:]
		// Verify OTP
		log.Println("OTP code received:", string(otp))
		if utils.VerifyOTP(string(otp)) {
			wt.shouldVerifyOTP = false
			err := wt.sentOTPMessage("\n\rcode correct\n\r")
			if err != nil {
				return errors.Wrapf(err, "failed to send OTP message")
			}
		} else {
			err := wt.sentOTPMessage("\n\rcode incorrect\n\rPlease enter the OTP code:")
			if err != nil {
				return errors.Wrapf(err, "failed to send OTP message")
			}
			wt.writeMutex.Lock()
			wt.lastFailedOTP = time.Now()
			wt.writeMutex.Unlock()
		}
	default:
		return errors.Errorf("unknown message type `%c`", data[0])
	}

	return nil
}

func (wt *WebTTY) sentOTPMessage(message string) error {
	msg := map[string]string{
		"message":      message,
		"shouldVerify": strconv.FormatBool(wt.shouldVerifyOTP),
	}
	msgBytes, _ := json.Marshal(msg)
	err := wt.masterWrite(append([]byte{OTPRequest}, []byte(base64.StdEncoding.EncodeToString(msgBytes))...))
	if err != nil {
		return errors.Wrapf(err, "failed to send message to master")
	}
	return nil
}

type argResizeTerminal struct {
	Columns float64
	Rows    float64
}
