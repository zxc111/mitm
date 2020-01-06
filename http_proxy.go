package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
)

const (
	proxyPath = "0.0.0.0:10001"
)

var CertMapping *certMapping

func init() {
	CertMapping = new(certMapping)
	CertMapping.Map = make(map[string]*tls.Certificate)
}

// openssl req -new -x509 -days 3650 -keyout CARoot1024.key -out CARoot1024.crt
func httpProxy() {
	server := &http.Server{
		Addr: proxyPath,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handler(w, r)
		}),
	}
	log.Fatal(server.ListenAndServe())

}
func closeConn(conn io.Closer) {
	err := conn.Close()
	if err != nil {
	}
}
func handler(w http.ResponseWriter, r *http.Request) {
	r.Header.Del("Proxy-Connection")
	hijacker, _ := w.(http.Hijacker)
	clientConn, _, err := hijacker.Hijack()
	switch r.Method {
	case http.MethodConnect:
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		remote := "http://" + r.URL.Host
		CreateTunnel(clientConn, remote, r)
	default:
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		OtherMethod(r, r.RequestURI, clientConn, w)
	}
	defer closeConn(clientConn)

}

// not connectMethod method (http not https,don't need tunnel)
func OtherMethod(from *http.Request, remoteAddr string, to net.Conn, w http.ResponseWriter) {

	dump, err := httputil.DumpRequest(from, true)
	if err != nil {
		log.Println(err)
	}

	req, err := http.NewRequest(
		http.MethodGet,
		remoteAddr,
		bytes.NewBuffer(dump),
	)
	if err != nil {
		log.Println(err)
		return
	}

	req.Header = from.Header
	cli := http.Client{}
	resp, err := cli.Do(req)
	if err != nil {
		log.Println(err)
		return
	}
	defer closeConn(resp.Body)

	to.Write([]byte("HTTP/1.1 200 OK\r\n"))

	for k, v := range resp.Header {
		to.Write([]byte(fmt.Sprintf("%s: %s\r\n", k, v[0])))
	}
	to.Write([]byte("\r\n"))

	io.Copy(to, resp.Body)

}

func CreateTunnel(from net.Conn, remoteAddr string, r *http.Request) {
	remoteAddr = strings.Replace(remoteAddr, "http://", "", -1)
	remoteAddr = strings.Replace(remoteAddr, "https://", "", -1)
	host := strings.Split(r.Host, ":")[0]

	send(host, from, true, r)
}

func send(host string, from net.Conn, https bool, r *http.Request) {

	cer := CertMapping.get(host)

	ml := mitmListener{}
	if https {
		//a, _ := x509.ParseCertificate(cer.Certificate[0])
		config := &tls.Config{
			Certificates:       []tls.Certificate{*cer},
			InsecureSkipVerify: true,
			ServerName:         host,
		}
		conn := tls.Server(from, config)
		ml = mitmListener{conn}
	} else {
		ml = mitmListener{from}
	}
	wg := new(sync.WaitGroup)
	wg.Add(1)
	go func(wg *sync.WaitGroup) {
		err := http.Serve(&ml, http.HandlerFunc(func(resp2 http.ResponseWriter, req2 *http.Request) {
			body, err := ioutil.ReadAll(req2.Body)
			if err != nil {
				resp2.WriteHeader(500)
				return
			}
			defer req2.Body.Close()
			schema := "http://"
			if https {
				schema = "https://"
			}
			url := schema + req2.Host + req2.URL.String()

			req, _ := http.NewRequest(req2.Method, url, bytes.NewBuffer(body))
			if https {
				req.Header = req2.Header
			} else {
				req.Header = r.Header
			}
			cli := http.Client{}
			resp, err := cli.Do(req)
			if err != nil {
				log.Println(err)
				resp2.WriteHeader(http.StatusBadGateway)
				return
			}
			for k, v := range resp.Header {
				resp2.Header().Set(k, v[0])

			}
			resp2.WriteHeader(resp.StatusCode)
			respBody, err := ioutil.ReadAll(resp.Body)

			if err != nil {
				log.Println(err)

				resp2.WriteHeader(500)
				return
			}
			defer resp.Body.Close()
			resp2.Write(respBody)
		}))
		if err != nil {
			if err == io.EOF {
				return
			}
			log.Printf("Error serving mitm'ed connection: %s", err)
		}

	}(wg)
	_, _ = fmt.Fprint(from, "HTTP/1.1 200 Connection Established\r\n\r\n")
	wg.Wait()
}

type mitmListener struct {
	conn net.Conn
}

func (listener *mitmListener) Accept() (net.Conn, error) {
	if listener.conn != nil {
		conn := listener.conn
		listener.conn = nil
		return conn, nil
	} else {
		return nil, io.EOF
	}
}

func (listener *mitmListener) Close() error {
	return nil
}

func (listener *mitmListener) Addr() net.Addr {
	return nil
}

type certMapping struct {
	Map map[string]*tls.Certificate
	sync.RWMutex
}

func (c *certMapping) get(host string) *tls.Certificate {
	c.RLock()
	if cert, ok := c.Map[host]; ok {
		c.RUnlock()
		return cert
	}

	c.RUnlock()
	c.Lock()

	if cert, ok := c.Map[host]; ok {
		c.Unlock()
		return cert
	}
	k, err := newKey(host)
	if err != nil {
		log.Fatal(err)
	}
	c.Map[host] = k
	c.Unlock()
	return k
}
