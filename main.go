package main

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"

	"golang.org/x/crypto/chacha20"
)

var GlobalKey []byte

type CipherStream interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Close() error
}

type Chacha20Stream struct {
	key     []byte
	encoder *chacha20.Cipher
	decoder *chacha20.Cipher
	conn    net.Conn
}

func NewChacha20Stream(key []byte, conn net.Conn) (*Chacha20Stream, error) {
	s := &Chacha20Stream{
		key:  key, // should be exactly​ 32 bytes
		conn: conn,
	}

	var err error
	nonce := make([]byte, chacha20.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	s.encoder, err = chacha20.NewUnauthenticatedCipher(s.key, nonce)
	if err != nil {
		return nil, err
	}

	if n, err := s.conn.Write(nonce); err != nil || n != len(nonce) {
		return nil, errors.New("write nonce failed: " + err.Error())
	}
	return s, nil
}

func (s *Chacha20Stream) Read(p []byte) (int, error) {
	if s.decoder == nil {
		nonce := make([]byte, chacha20.NonceSizeX)
		if n, err := io.ReadAtLeast(s.conn, nonce, len(nonce)); err != nil || n != len(nonce) {
			return n, errors.New("can't read nonce from stream: " + err.Error())
		}
		decoder, err := chacha20.NewUnauthenticatedCipher(s.key, nonce)
		if err != nil {
			return 0, errors.New("generate decoder failed: " + err.Error())
		}
		s.decoder = decoder
	}

	n, err := s.conn.Read(p)
	if err != nil || n == 0 {
		return n, err
	}

	dst := make([]byte, n)
	pn := p[:n]
	s.decoder.XORKeyStream(dst, pn)
	copy(pn, dst)
	return n, nil
}

func (s *Chacha20Stream) Write(p []byte) (int, error) {
	dst := make([]byte, len(p))
	s.encoder.XORKeyStream(dst, p)
	return s.conn.Write(dst)
}

func (s *Chacha20Stream) Close() error {
	return s.conn.Close()
}

func main() {
	listenAddr := flag.String("listenAddr", "0.0.0.0:9933", "Local Server For Client / Remote Server For Local")
	remoteAddr := flag.String("remoteAddr", "192.168.193.156:3399", "Remote Server For Local / None")
	role := flag.String("role", "Local", "Local or Remote")
	secret := flag.String("secret", "GoTunnel", "Token")
	GlobalKey = []byte(fmt.Sprintf("%x", md5.Sum([]byte(*secret))))
	flag.Parse()

	listener, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("Listen failed: %v\n", err)
	} else {
		log.Printf("Listen on %s\n", *listenAddr)
	}

	if *role == "Local" {
		localServer(listener, *remoteAddr)
	} else if *role == "Remote" {
		remoteServer(listener)
	} else {
		log.Fatal("Invalid role")
	}
}

func localServer(listener net.Listener, remoteAddr string) {
	for {
		src, err := listener.Accept()
		if err != nil {
			log.Printf("Accept connect failed: %v\n", err)
		} else {
			log.Printf("Accept connect from local: %v\n", src.RemoteAddr())
			go encryptRelay(src, remoteAddr)
		}
	}
}

func remoteServer(listener net.Listener) {
	for {
		client, err := listener.Accept()
		if err != nil {
			log.Printf("Accept connect failed: %v\n", err)
		} else {
			log.Printf("Accept connect from remote: %v\n", client.RemoteAddr())
			go decryptRelay(client)
		}
	}
}

func encryptRelay(src net.Conn, remoteAddr string) {
	dst, err := net.Dial("tcp", remoteAddr)
	if err != nil {
		src.Close()
		log.Fatalf("The remote server connection failed: %s", err)
	}
	log.Printf("Connect to remote server: %v\n", dst.RemoteAddr())

	var cipherSrc, cipherDst CipherStream
	cipherSrc = src
	cipherDst, err = NewChacha20Stream(GlobalKey, dst)
	if err != nil {
		src.Close()
		dst.Close()
	}

	Socks5Forward(cipherSrc, cipherDst)
}

func decryptRelay(src net.Conn) {
	var cipherSrc, cipherDst CipherStream
	cipherSrc, err := NewChacha20Stream(GlobalKey, src)
	if err != nil {
		src.Close()
	}

	if err := Socks5Auth(cipherSrc); err != nil {
		fmt.Println("auth error:", err)
		src.Close()
		return
	}

	dst, err := Socks5Connect(cipherSrc)
	if err != nil {
		fmt.Println("connect error:", err)
		src.Close()
		return
	}

	cipherDst = dst

	Socks5Forward(cipherSrc, cipherDst)
}

func Socks5Forward(client, target CipherStream) {
	forward := func(src, dst CipherStream) {
		defer src.Close()
		defer dst.Close()
		io.Copy(dst, src)
	}
	go forward(client, target)
	go forward(target, client)
}

func Socks5Auth(client CipherStream) (err error) {
	buf := make([]byte, 256)

	// 读取 VER 和 NMETHODS
	n, err := io.ReadFull(client, buf[:2])
	if n != 2 {
		return errors.New("reading header: " + err.Error())
	}

	ver, nMethods := int(buf[0]), int(buf[1])
	if ver != 5 {
		return errors.New("invalid version")
	}

	// 读取 METHODS 列表
	n, err = io.ReadFull(client, buf[:nMethods])
	if n != nMethods {
		return errors.New("reading methods: " + err.Error())
	}

	//无需认证
	n, err = client.Write([]byte{0x05, 0x00})
	if n != 2 || err != nil {
		return errors.New("write rsp: " + err.Error())
	}

	return nil
}

func Socks5Connect(client CipherStream) (net.Conn, error) {
	buf := make([]byte, 256)

	n, err := io.ReadFull(client, buf[:4])
	if n != 4 {
		return nil, errors.New("read header: " + err.Error())
	}

	ver, cmd, _, atyp := buf[0], buf[1], buf[2], buf[3]
	if ver != 5 || cmd != 1 {
		return nil, errors.New("invalid ver/cmd")
	}

	addr := ""
	switch atyp {
	case 1:
		n, err = io.ReadFull(client, buf[:4])
		if n != 4 {
			return nil, errors.New("invalid IPv4: " + err.Error())
		}
		addr = fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])

	case 3:
		n, err = io.ReadFull(client, buf[:1])
		if n != 1 {
			return nil, errors.New("invalid hostname: " + err.Error())
		}
		addrLen := int(buf[0])

		n, err = io.ReadFull(client, buf[:addrLen])
		if n != addrLen {
			return nil, errors.New("invalid hostname: " + err.Error())
		}
		addr = string(buf[:addrLen])

	case 4:
		return nil, errors.New("IPv6: no supported yet")

	default:
		return nil, errors.New("invalid atyp")
	}

	n, err = io.ReadFull(client, buf[:2])
	if n != 2 {
		return nil, errors.New("read port: " + err.Error())
	}
	port := binary.BigEndian.Uint16(buf[:2])

	destAddrPort := fmt.Sprintf("%s:%d", addr, port)
	dest, err := net.Dial("tcp", destAddrPort)
	if err != nil {
		return nil, errors.New("dial dst: " + err.Error())
	}

	n, err = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	if err != nil || n != 10 {
		dest.Close()
		return nil, errors.New("write rsp: " + err.Error())
	}

	return dest, nil
}
