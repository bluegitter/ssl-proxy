package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/suyashkumar/ssl-proxy/gen"
	"github.com/suyashkumar/ssl-proxy/reverseproxy"
	"golang.org/x/crypto/acme/autocert"
)

var (
	to           = flag.String("to", "http://127.0.0.1:80", "the address and port for which to proxy requests to")
	fromURL      = flag.String("from", "127.0.0.1:4430", "the tcp address and port this proxy should listen for requests on")
	certFile     = flag.String("cert", "cert.pem", "path to a tls certificate file. If not provided, ssl-proxy will generate one for you in ~/.ssl-proxy/")
	keyFile      = flag.String("key", "key.pem", "path to a private key file. If not provided, ssl-proxy will generate one for you in ~/.ssl-proxy/")
	domain       = flag.String("domain", "", "domain to mint letsencrypt certificates for. Usage of this parameter implies acceptance of the LetsEncrypt terms of service.")
	redirectHTTP = flag.Bool("redirectHTTP", false, "if true, redirects http requests from port 80 to https at your fromURL")
	routers      = flag.String("routers", "", "Routing rules in the form /path=target or host=/path=target, separated by commas. e.g. /api1=http://127.0.0.1:8001,api.com=/api2=https://127.0.0.1:8002")
	routersFile  = flag.String("routersFile", "", "JSON string or file path for routing rules, e.g. '[{\"host\":\"a.com\",\"target\":\"http://127.0.0.1:8001\"}] or routers.json'")
	root         = flag.String("root", "", "If set, serve static files from this directory as the default handler. Cannot be used with -to.")
	certOrg      = flag.String("certOrg", "ssl-proxy", "Organization for generated certificate")
	certDNS      = flag.String("certDNS", "localhost", "Comma-separated DNS names for generated certificate")
	certIP       = flag.String("certIP", "", "Comma-separated IP addresses for generated certificate")
)

const (
	DefaultCertFile = "cert.pem"
	DefaultKeyFile  = "key.pem"
	HTTPSPrefix     = "https://"
	HTTPPrefix      = "http://"
)

// Route 路由规则结构体
// Host、Path 可选，Target 必填
// e.g. {"host":"a.com","path":"/api","target":"http://127.0.0.1:8001"}
type Route struct {
	Host   string `json:"host"`
	Path   string `json:"path"`
	Target string `json:"target"`
}

// RouteTable 路由表
var routeTable []Route

// 解析路由表
func loadRoutersFile(routersFileArg string) ([]Route, error) {
	var data []byte
	var err error
	if routersFileArg == "" {
		return nil, nil
	}
	if strings.HasSuffix(routersFileArg, ".json") {
		data, err = os.ReadFile(routersFileArg)
		if err != nil {
			return nil, err
		}
	} else {
		data = []byte(routersFileArg)
	}
	var routes []Route
	err = json.Unmarshal(data, &routes)
	if err != nil {
		return nil, err
	}
	return routes, nil
}

// 解析 -routers 参数
func parseRouters(routersArg string) ([]Route, error) {
	if routersArg == "" {
		return nil, nil
	}
	var routes []Route
	items := strings.Split(routersArg, ",")
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		var host, path, target string
		left, right, found := strings.Cut(item, "=")
		if !found {
			continue
		}
		target = right
		if strings.HasPrefix(left, "/") {
			// /path=target
			path = left
		} else if strings.Contains(left, "/") {
			// host/path=target
			parts := strings.SplitN(left, "/", 2)
			host = parts[0]
			path = "/" + parts[1]
		} else {
			// host=target
			host = left
		}
		routes = append(routes, Route{Host: host, Path: path, Target: target})
	}
	return routes, nil
}

// 解析 IP 列表
func parseIPList(ipStr string) []net.IP {
	if ipStr == "" {
		return nil
	}
	parts := strings.Split(ipStr, ",")
	var ips []net.IP
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		ip := net.ParseIP(p)
		if ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips
}

// 路由分发 Handler
func routeHandler(routes []Route, defaultProxy http.Handler) http.HandlerFunc {
	// 预构建所有 ReverseProxy
	proxies := map[string]http.Handler{}
	for _, r := range routes {
		u, err := url.Parse(r.Target)
		if err != nil {
			log.Printf("Invalid target url in route: %v", r)
			continue
		}
		proxies[r.Host+"|"+r.Path] = reverseproxy.Build(u)
	}
	return func(w http.ResponseWriter, req *http.Request) {
		// 优先 Host+Path > Host > Path > 默认
		host := req.Host
		path := req.URL.Path
		for _, r := range routes {
			if r.Host != "" && r.Path != "" {
				if host == r.Host && strings.HasPrefix(path, r.Path) {
					proxies[r.Host+"|"+r.Path].ServeHTTP(w, req)
					return
				}
			}
		}
		for _, r := range routes {
			if r.Host != "" && r.Path == "" {
				if host == r.Host {
					proxies[r.Host+"|"].ServeHTTP(w, req)
					return
				}
			}
		}
		for _, r := range routes {
			if r.Host == "" && r.Path != "" {
				if strings.HasPrefix(path, r.Path) {
					proxies["|"+r.Path].ServeHTTP(w, req)
					return
				}
			}
		}
		// 默认
		if defaultProxy != nil {
			defaultProxy.ServeHTTP(w, req)
			return
		}
		http.NotFound(w, req)
	}
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	return err == nil && !info.IsDir()
}

func main() {
	flag.Parse()
	var err error // 只声明一次

	if *root != "" && *to != "" && *to != "http://127.0.0.1:80" {
		log.Fatal("The -root and -to parameters cannot be used at the same time!")
	}

	validCertFile := *certFile != ""
	validKeyFile := *keyFile != ""
	validDomain := *domain != ""

	// 检查证书和密钥文件是否存在，不存在则自动生成
	if (!validCertFile || !fileExists(*certFile)) || (!validKeyFile || !fileExists(*keyFile)) {
		*certFile = DefaultCertFile
		*keyFile = DefaultKeyFile

		log.Printf("No existing cert or key specified or file missing, generating self-signed certs for use (%s, %s)\n", *certFile, *keyFile)

		org := *certOrg
		dnsNames := strings.Split(*certDNS, ",")
		for i := range dnsNames {
			dnsNames[i] = strings.TrimSpace(dnsNames[i])
		}
		ipAddresses := parseIPList(*certIP)

		certBuf, keyBuf, fingerprint, err := gen.Keys(365*24*time.Hour, org, dnsNames, ipAddresses)
		if err != nil {
			log.Fatal("Error generating default keys", err)
		}

		certOut, err := os.Create(*certFile)
		if err != nil {
			log.Fatal("Unable to create cert file", err)
		}
		certOut.Write(certBuf.Bytes())

		keyOut, err := os.OpenFile(*keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			log.Fatal("Unable to create the key file", err)
		}
		keyOut.Write(keyBuf.Bytes())

		log.Printf("SHA256 Fingerprint: % X", fingerprint)
	}

	// Ensure the to URL is in the right form
	if !strings.HasPrefix(*to, HTTPPrefix) && !strings.HasPrefix(*to, HTTPSPrefix) {
		*to = HTTPPrefix + *to
		log.Println("Assuming -to URL is using http://")
	}

	// Parse toURL as a URL
	toURL, err := url.Parse(*to)
	if err != nil {
		log.Fatal("Unable to parse 'to' url: ", err)
	}

	// 解析路由表
	var routesList []Route
	if *routers != "" {
		routesList, err = parseRouters(*routers)
		if err != nil {
			log.Fatalf("Failed to parse routers: %v", err)
		}
	} else if *routersFile != "" {
		routesList, err = loadRoutersFile(*routersFile)
		if err != nil {
			log.Fatalf("Failed to load routersFile: %v", err)
		}
	}
	log.Printf("DEBUG: routers=%v", routesList)

	// Setup reverse proxy ServeMux
	var mux *http.ServeMux
	if len(routesList) > 0 {
		mux = http.NewServeMux()
		// 默认处理器
		var defaultHandler http.Handler
		if *root != "" {
			defaultHandler = http.FileServer(http.Dir(*root))
		} else if *to != "" {
			toURL, err := url.Parse(*to)
			if err == nil {
				defaultHandler = reverseproxy.Build(toURL)
			}
		}
		mux.HandleFunc("/", routeHandler(routesList, defaultHandler))
		log.Printf(green("Proxying with custom routes from https://%s (SSL/TLS)"), *fromURL)
	} else if *root != "" {
		mux = http.NewServeMux()
		mux.Handle("/", http.FileServer(http.Dir(*root)))
		log.Printf(green("Serving static files from %s at https://%s (SSL/TLS)"), *root, *fromURL)
	} else {
		// 兼容原有单一目标
		toURL, err = url.Parse(*to)
		if err != nil {
			log.Fatal("Unable to parse 'to' url: ", err)
		}
		p := reverseproxy.Build(toURL)
		mux = http.NewServeMux()
		mux.Handle("/", p)
		log.Printf(green("Proxying calls from https://%s (SSL/TLS) to %s"), *fromURL, toURL)
	}

	// Redirect http requests on port 80 to TLS port using https
	if *redirectHTTP {
		// Redirect to fromURL by default, unless a domain is specified--in that case, redirect using the public facing
		// domain
		redirectURL := *fromURL
		if validDomain {
			redirectURL = *domain
		}
		redirectTLS := func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://"+redirectURL+r.RequestURI, http.StatusMovedPermanently)
		}
		go func() {
			log.Println(
				fmt.Sprintf("Also redirecting https requests on port 80 to https requests on %s", redirectURL))
			err := http.ListenAndServe(":80", http.HandlerFunc(redirectTLS))
			if err != nil {
				log.Println("HTTP redirection server failure")
				log.Println(err)
			}
		}()
	}

	// Determine if we should serve over TLS with autogenerated LetsEncrypt certificates or not
	if validDomain {
		// Domain is present, use autocert
		// TODO: validate domain (though, autocert may do this)
		// TODO: for some reason this seems to only work on :443
		log.Printf("Domain specified, using LetsEncrypt to autogenerate and serve certs for %s\n", *domain)
		if !strings.HasSuffix(*fromURL, ":443") {
			log.Println("WARN: Right now, you must serve on port :443 to use autogenerated LetsEncrypt certs using the -domain flag, this may NOT WORK")
		}
		m := &autocert.Manager{
			Cache:      autocert.DirCache("certs"),
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(*domain),
		}
		s := &http.Server{
			Addr:      *fromURL,
			TLSConfig: m.TLSConfig(),
		}
		s.Handler = mux
		log.Fatal(s.ListenAndServeTLS("", ""))
	} else {
		// Domain is not provided, serve TLS using provided/generated certificate files
		log.Fatal(http.ListenAndServeTLS(*fromURL, *certFile, *keyFile, mux))
	}

}

// green takes an input string and returns it with the proper ANSI escape codes to render it green-colored
// in a supported terminal.
// TODO: if more colors used in the future, generalize or pull in an external pkg
func green(in string) string {
	return fmt.Sprintf("\033[0;32m%s\033[0;0m", in)
}
