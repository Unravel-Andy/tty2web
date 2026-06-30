package utils

import (
	"log"
	"time"

	"github.com/xlzd/gotp"
)

var (
	otpSecret   = ""
	otpInterval = 180 // 3 minutes
	otpDigit    = 8   // 1 hour
)

// SetOTPSecret sets the OTP secret for the application.
func SetOTPSecret(secret string, debug bool) {
	otpSecret = secret
	if debug {
		totp := gotp.NewTOTP(
			otpSecret,
			otpDigit,
			otpInterval,
			nil,
		)
		// Generate a new OTP and print it
		otpCode := totp.Now()
		// Print the OTP code
		log.Println("OTP code:", otpCode)
	}
}

func SetOTPInterval(interval int) {
	if interval >= 30 {
		otpInterval = interval
	}
}

func SetOTPDigit(digit int) {
	if digit >= 6 {
		otpDigit = digit
	} else {
		log.Println("OTP digit is out of range must be greater than or equal 6")
	}
}

func VerifyOTP(token string) bool {
	if otpSecret == "" {
		return false
	}

	// Implement the OTP verification logic here.
	totp := gotp.NewTOTP(
		otpSecret,
		otpDigit,
		otpInterval,
		nil,
	)

	return totp.Verify(token, time.Now().Unix())
}
