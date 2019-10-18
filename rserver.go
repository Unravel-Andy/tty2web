package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"bufio"
	"time"
	"github.com/hashicorp/yamux"
	"strings"
)

var proxytout = time.Millisecond * 1000 //timeout for wait magicbytes
var session *yamux.Session
// Catches yamux connecting to us
func listenForAgent(address string, certificate string, agentpassword string) {
	var err error
	var cer tls.Certificate

        if agentpassword == "" {
		agentpassword = RandString(64)
                log.Println("No password specified. Make sure to use generated one at client. Generated password is " + agentpassword)
	}

	if certificate == "" {
		cer, err = getRandomTLS(2048)
		log.Println("No TLS certificate. Generated random one.")
	} else {
		cer, err = tls.LoadX509KeyPair(certificate+".crt", certificate+".key")
	}
	if err != nil {
		log.Println(err)
		return
	}
	log.Println("Listening for agent")
	config := &tls.Config{Certificates: []tls.Certificate{cer}}
	//ln, err := net.Listen("tcp", address)
	ln, err := tls.Listen("tcp", address, config)
	if err != nil {
		return
	}
	for {
		conn, err := ln.Accept()
		conn.RemoteAddr()
		log.Printf("Got a SSL connection from %v: ", conn.RemoteAddr())
		if err != nil {
			fmt.Fprintf(os.Stderr, "Errors accepting!")
		}

		reader := bufio.NewReader(conn)

		//read only 64 bytes with timeout=1-3 sec. So we haven't delay with browsers
		conn.SetReadDeadline(time.Now().Add(proxytout))
		statusb := make([]byte, 64)
		_, _ = io.ReadFull(reader, statusb)

		//Alternatively  - read all bytes with timeout=1-3 sec. So we have delay with browsers, but get all GET request
		//conn.SetReadDeadline(time.Now().Add(proxytout))
		//statusb,_ := ioutil.ReadAll(magicBuf)

		//log.Printf("magic bytes: %v",statusb[:6])
		//if hex.EncodeToString(statusb) != magicbytes {
		if string(statusb)[:len(agentpassword)] != agentpassword {
			//do HTTP checks
			log.Printf("Received request: %v", string(statusb[:64]))
			status := string(statusb)
			if strings.Contains(status, " HTTP/1.1") {
				httpresonse := "HTTP/1.1 301 Moved Permanently" +
					"\r\nContent-Type: text/html; charset=UTF-8" +
					"\r\nLocation: https://www.microsoft.com/" +
					"\r\nServer: Apache" +
					"\r\nContent-Length: 0" +
					"\r\nConnection: close" +
					"\r\n\r\n"

				conn.Write([]byte(httpresonse))
				conn.Close()
			} else {
				conn.Close()
			}

		} else {
			//magic bytes received.
			//disable socket read timeouts
			log.Printf("Got agent with correct authentication from %v", conn.RemoteAddr())
			conn.SetReadDeadline(time.Now().Add(100 * time.Hour))

			//Add connection to yamux
			session, err = yamux.Client(conn, nil)
		}
	}
}

// Catches clients and connects to yamux
func listenForClients(address string) error {
	log.Printf("Waiting for clients on %s", address)
	ln, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		// TODO dial socks5 through yamux and connect to conn

		if session == nil {
			conn.Close()
			continue
		}
		log.Printf("Got client from %v", conn.RemoteAddr())

		stream, err := session.Open()
		if err != nil {
			return err
		}

		// connect both of conn and stream

		go func() {
			log.Printf("Starting to copy conn to stream (%v)", conn.RemoteAddr())
			io.Copy(conn, stream)
			conn.Close()
		}()
		go func() {
			log.Printf("Starting to copy stream to conn (%v)", conn.RemoteAddr())
			io.Copy(stream, conn)
			stream.Close()
			log.Printf("Done copying stream to conn (%v)", conn.RemoteAddr())
		}()
	}
}
