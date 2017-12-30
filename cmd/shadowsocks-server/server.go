package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"glog"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
        "time"

	ss "github.com/shadowsocks/shadowsocks-go/shadowsocks"
)

const (
	idType  = 0 // address type index
	idIP0   = 1 // ip addres start index
	idDmLen = 1 // domain address length index
	idDm0   = 2 // domain address start index

	typeIPv4 = 1 // type is ipv4 address
	typeDm   = 3 // type is domain address
	typeIPv6 = 4 // type is ipv6 address

	lenIPv4     = net.IPv4len + 2 // ipv4 + 2port
	lenIPv6     = net.IPv6len + 2 // ipv6 + 2port
	lenDmBase   = 2               // 1addrLen + 2port, plus addrLen
	lenHmacSha1 = 10
)

var debug ss.DebugLog
var udp bool

func getRequest(conn *ss.Conn, auth bool) (host string, ota bool, err error) {
	ss.SetReadTimeout(conn)

	// buf size should at least have the same size with the largest possible
	// request size (when addrType is 3, domain name has at most 256 bytes)
	// 1(addrType) + 1(lenByte) + 255(max length address) + 2(port) + 10(hmac-sha1)
	buf := make([]byte, 269)
	// read till we get possible domain length field
	if _, err = io.ReadFull(conn, buf[:idType+1]); err != nil {
		return
	}

	var reqStart, reqEnd int
	addrType := buf[idType]
	switch addrType & ss.AddrMask {
	case typeIPv4:
		reqStart, reqEnd = idIP0, idIP0+lenIPv4
	case typeIPv6:
		reqStart, reqEnd = idIP0, idIP0+lenIPv6
	case typeDm:
		if _, err = io.ReadFull(conn, buf[idType+1:idDmLen+1]); err != nil {
			return
		}
		reqStart, reqEnd = idDm0, idDm0+int(buf[idDmLen])+lenDmBase
	default:
		err = fmt.Errorf("addr type %d(%d/%d) not supported", addrType&ss.AddrMask,addrType,ss.AddrMask)
		return
	}

	if _, err = io.ReadFull(conn, buf[reqStart:reqEnd]); err != nil {
		return
	}

	// Return string for typeIP is not most efficient, but browsers (Chrome,
	// Safari, Firefox) all seems using typeDm exclusively. So this is not a
	// big problem.
	switch addrType & ss.AddrMask {
	case typeIPv4:
		host = net.IP(buf[idIP0 : idIP0+net.IPv4len]).String()
	case typeIPv6:
		host = net.IP(buf[idIP0 : idIP0+net.IPv6len]).String()
	case typeDm:
		host = string(buf[idDm0 : idDm0+int(buf[idDmLen])])
	}
	// parse port
	port := binary.BigEndian.Uint16(buf[reqEnd-2 : reqEnd])
	host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	// if specified one time auth enabled, we should verify this
	if auth || addrType&ss.OneTimeAuthMask > 0 {
		ota = true
		if _, err = io.ReadFull(conn, buf[reqEnd:reqEnd+lenHmacSha1]); err != nil {
			return
		}
		iv := conn.GetIv()
		key := conn.GetKey()
		actualHmacSha1Buf := ss.HmacSha1(append(iv, key...), buf[:reqEnd])
		if !bytes.Equal(buf[reqEnd:reqEnd+lenHmacSha1], actualHmacSha1Buf) {
			err = fmt.Errorf("verify one time auth failed, iv=%s key=%s data=%s", iv, key, buf[:reqEnd])
			return
		}
	}
	return
}

const logCntDelta = 100

var connCnt int
var nextLogConnCnt int = logCntDelta

func handleConnection(conn *ss.Conn, auth bool) {
	var host string
        var porta string = strings.Split(conn.LocalAddr().String(),":")[1]
        var portb string = strings.Split(conn.RemoteAddr().String(),":")[1]
	connCnt++ // this maybe not accurate, but should be enough
        glog.V(2).Infof("handleconn(%s-%s)->Start to handle new conn of %d conns total...",portb,porta,connCnt)
	if connCnt-nextLogConnCnt >= 0 {
		// XXX There's no xadd in the atomic package, so it's difficult to log
		// the message only once with low cost. Also note nextLogConnCnt maybe
		// added twice for current peak connection number level.
		glog.Info("handleconn(%s-%s)->Number of client connections reaches %d\n", portb,porta,nextLogConnCnt)
		nextLogConnCnt += logCntDelta
	}

	// function arguments are always evaluated, so surround debug statement
	// with if statement
	if debug {
		glog.V(3).Infof("handleconn(%s-%s)->new client %s->%s\n", portb,porta,conn.RemoteAddr().String(), conn.LocalAddr())
	}
	closed := false
	defer func() {
		connCnt--
		if debug {
			glog.V(3).Infof("handleconn(%s-%s)->closed pipe %s<->%s (%d conns left)", portb,porta,conn.RemoteAddr(), host, connCnt)
		}
		if !closed {
                        glog.Infof("handleconn(%s-%s)->Closing conn %s<->%s\n", portb,porta,conn.RemoteAddr(), conn.LocalAddr())

			conn.Close()
		}
	}()

	host, ota, err := getRequest(conn, auth)
	if err != nil {
		glog.Errorf("handleconn(%s-%s)->error getting request", portb,porta,conn.RemoteAddr(), conn.LocalAddr(), err)
		//closed = true
		return
	}
	// ensure the host does not contain some illegal characters, NUL may panic on Win32
	if strings.ContainsRune(host, 0x00) {
                glog.Errorf("handleconn(%s-%s)->invalid domain name.",portb,porta)
		//closed = true
		return
	}
	glog.V(3).Infof("handleconn(%s-%s)->connecting", portb,porta,host)
	remote, err := net.DialTimeout("tcp", host, 2*time.Second)
	if err != nil {
		if ne, ok := err.(*net.OpError); ok && (ne.Err == syscall.EMFILE || ne.Err == syscall.ENFILE) {
			// log too many open file error
			// EMFILE is process reaches open file limits, ENFILE is system limit
			glog.Errorf("handleconn(%s-%s)->dial error:", portb,porta,err)
		} else {
			glog.Errorf("handleconn(%s-%s)->error connecting to:", portb,porta, host, err)
		}
		return
	}
	defer func() {
		if !closed {
                        glog.V(3).Infof("handleconn(%s-%s)->Closing remote conn %s<->%s\n", portb,porta,conn.LocalAddr(), host)
			remote.Close()
		}
	}()
	if debug {
		glog.V(3).Infof("handleconn(%s-%s)->piping %s<->%s ota=%v connOta=%v", portb,porta,conn.RemoteAddr(), host, ota, conn.IsOta())
	}
	if ota {
		go ss.PipeThenCloseOta(conn, remote)
	} else {
		go ss.PipeThenClose(conn, remote)
	}
        if debug {
            glog.V(3).Infof("handleconn(%s-%s)->go piped %s-->%s:",portb,porta,conn.RemoteAddr(),host)
        }
	ss.PipeThenClose(remote, conn)
        if debug {
            glog.V(3).Infof("handleconn(%s-%s)->pipe closed %s-->%s", portb,porta,host, conn.RemoteAddr())
        }
	closed = true
	return
}

type PortListener struct {
	password string
	listener net.Listener
        //lnFile *os.File
}

type UDPListener struct {
	password string
	listener *net.UDPConn
}

type PasswdManager struct {
	sync.Mutex
	portListener map[string]*PortListener
	udpListener  map[string]*UDPListener
}

func (pm *PasswdManager) add(port, password string, listener net.Listener) {
	pm.Lock()
	pm.portListener[port] = &PortListener{password, listener}
	pm.Unlock()
}

func (pm *PasswdManager) addUDP(port, password string, listener *net.UDPConn) {
	pm.Lock()
	pm.udpListener[port] = &UDPListener{password, listener}
	pm.Unlock()
}

func (pm *PasswdManager) get(port string) (pl *PortListener, ok bool) {
	pm.Lock()
	pl, ok = pm.portListener[port]
	pm.Unlock()
	return
}

func (pm *PasswdManager) getUDP(port string) (pl *UDPListener, ok bool) {
	pm.Lock()
	pl, ok = pm.udpListener[port]
	pm.Unlock()
	return
}

func (pm *PasswdManager) del(port string) {
	pl, ok := pm.get(port)
	if !ok {
		return
	}
	if udp {
		upl, ok := pm.getUDP(port)
		if !ok {
			return
		}
		upl.listener.Close()
	}
	pl.listener.Close()
        //pl.lnFile.Close()
	pm.Lock()
	delete(pm.portListener, port)
	if udp {
		delete(pm.udpListener, port)
	}
	pm.Unlock()
}

// Update port password would first close a port and restart listening on that
// port. A different approach would be directly change the password used by
// that port, but that requires **sharing** password between the port listener
// and password manager.
func (pm *PasswdManager) updatePortPasswd(port, password string, auth bool) {
	pl, ok := pm.get(port)
	if !ok {
		glog.Infof("new port %s added\n", port)
	} else {
		if pl.password == password {
			return
		}
		glog.Infof("closing port %s to update password\n", port)
		pl.listener.Close()
		//log.Printf("closing file of port %s to update password\n", port)
                //pl.lnFile.Close()
		//log.Printf("sleeping 100 millisecend ...\n", port)
                time.Sleep(100 * time.Millisecond)
	}
	// run will add the new port listener to passwdManager.
	// So there maybe concurrent access to passwdManager and we need lock to protect it.
	go run(port, password, auth)
	if udp {
		pl, _ := pm.getUDP(port)
		pl.listener.Close()
		go runUDP(port, password, auth)
	}
}

var passwdManager = PasswdManager{portListener: map[string]*PortListener{}, udpListener: map[string]*UDPListener{}}

func updatePasswd() {
	glog.Info("updating password")
	newconfig, err := ss.ParseConfig(configFile)
	if err != nil {
		glog.Errorf("error parsing config file %s to update password: %s\n", configFile, err)
		return
	}
	oldconfig := config
	config = newconfig

	if err = unifyPortPassword(config); err != nil {
		return
	}
	for port, passwd := range config.PortPassword {
		passwdManager.updatePortPasswd(port, passwd, config.Auth)
		if oldconfig.PortPassword != nil {
                        glog.Infof("deleting port %s...\n", port)
			delete(oldconfig.PortPassword, port)
		}
	}
	// port password still left in the old config should be closed
	for port, _ := range oldconfig.PortPassword {
		glog.Infof("closing port %s as it's deleted\n", port)
		passwdManager.del(port)
	}
	glog.Info("password updated")
}

func waitSignal() {
	var sigChan = make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP, os.Interrupt, os.Kill)
	for sig := range sigChan {
		if sig == syscall.SIGHUP {
			updatePasswd()
                } else if (sig == os.Interrupt || sig == os.Kill) {
                        glog.Flush()
                        os.Exit(0)
                } else {
			// is this going to happen?
			glog.Infof("caught signal %s, exit", sig)
			os.Exit(0)
		}
	}
}

func run(port, password string, auth bool) {
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		glog.Errorf("error listening port %d: %s\n", port, err)
		os.Exit(1)
	}
        //lnFile, err := ln.(*net.TCPListener).File()
	//if err != nil {
	//	log.Printf("error get listener files port %v: %v\n", port, err)
//	}
	passwdManager.add(port, password, ln)
	var cipher *ss.Cipher
	glog.Infof("server listening port %s...\n", port)
	for {
		conn, err := ln.Accept()
                if err != nil {
                       glog.Errorf("run(%s)->%s",port,err)
                       return
                }
                glog.V(2).Infof("New connection accepted..%s",conn.RemoteAddr())
		if err != nil {
			// listener maybe closed to update password
			glog.Errorf("accept error: %s\n", err)
			return
		}
		// Creating cipher upon first connection.
		if cipher == nil {
			glog.Info("creating cipher for port:", port)
			cipher, err = ss.NewCipher(config.Method, password)
			if err != nil {
				glog.Errorf("Error generating cipher for port: %s %s\n", port, err)
				conn.Close()
				continue
			}
		}
		go handleConnection(ss.NewConn(conn, cipher.Copy()), auth)
	}
}

func runUDP(port, password string, auth bool) {
	var cipher *ss.Cipher
	port_i, _ := strconv.Atoi(port)
	glog.Infof("listening udp port %s\n", port)
	conn, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.IPv6zero,
		Port: port_i,
	})
	passwdManager.addUDP(port, password, conn)
	if err != nil {
		glog.Errorf("error listening udp port %s: %s\n", port, err)
		return
	}
	defer conn.Close()
	cipher, err = ss.NewCipher(config.Method, password)
	if err != nil {
		glog.Errorf("Error generating cipher for udp port: %s %s\n", port, err)
		conn.Close()
	}
	SecurePacketConn := ss.NewSecurePacketConn(conn, cipher.Copy(), auth)
	for {
		if err := ss.ReadAndHandleUDPReq(SecurePacketConn); err != nil {
			glog.V(3).Info(err)
		}
	}
}

func enoughOptions(config *ss.Config) bool {
	return config.ServerPort != 0 && config.Password != ""
}

func unifyPortPassword(config *ss.Config) (err error) {
	if len(config.PortPassword) == 0 { // this handles both nil PortPassword and empty one
		if !enoughOptions(config) {
			fmt.Fprintln(os.Stderr, "must specify both port and password")
			return errors.New("not enough options")
		}
		port := strconv.Itoa(config.ServerPort)
		config.PortPassword = map[string]string{port: config.Password}
	} else {
		if config.Password != "" || config.ServerPort != 0 {
			fmt.Fprintln(os.Stderr, "given port_password, ignore server_port and password option")
		}
	}
	return
}

var configFile string
var config *ss.Config

func main() {
	//log.SetOutput(os.Stdout)

	var cmdConfig ss.Config
	var printVer bool
	var core int

	flag.BoolVar(&printVer, "version", false, "print version")
	flag.StringVar(&configFile, "c", "config.json", "specify config file")
	flag.StringVar(&cmdConfig.Password, "k", "", "password")
	flag.IntVar(&cmdConfig.ServerPort, "p", 0, "server port")
	flag.IntVar(&cmdConfig.Timeout, "t", 300, "timeout in seconds")
	flag.StringVar(&cmdConfig.Method, "m", "", "encryption method, default: aes-256-cfb")
	flag.IntVar(&core, "core", 0, "maximum number of CPU cores to use, default is determinied by Go runtime")
	flag.BoolVar((*bool)(&debug), "d", false, "print debug message")
	flag.BoolVar(&udp, "u", false, "UDP Relay")
        flag.Set("log_dir","/tmp")
        flag.Set("alsologtostderr","true")
	flag.Parse()

	if printVer {
		ss.PrintVersion()
		os.Exit(0)
	}

	ss.SetDebug(debug)

	if strings.HasSuffix(cmdConfig.Method, "-auth") {
		cmdConfig.Method = cmdConfig.Method[:len(cmdConfig.Method)-5]
		cmdConfig.Auth = true
	}

	var err error
	config, err = ss.ParseConfig(configFile)
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "error reading %s: %s\n", configFile, err)
			os.Exit(1)
		}
		config = &cmdConfig
		ss.UpdateConfig(config, config)
	} else {
		ss.UpdateConfig(config, &cmdConfig)
	}
	if config.Method == "" {
		config.Method = "aes-256-cfb"
	}
	if err = ss.CheckCipherMethod(config.Method); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err = unifyPortPassword(config); err != nil {
		os.Exit(1)
	}
	if core > 0 {
		runtime.GOMAXPROCS(core)
	}
	for port, password := range config.PortPassword {
		go run(port, password, config.Auth)
		if udp {
			go runUDP(port, password, config.Auth)
		}
	}

	waitSignal()
}
