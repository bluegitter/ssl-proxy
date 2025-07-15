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
	"os/exec"
	"strings"
	"time"

	"github.com/suyashkumar/ssl-proxy/gen"
	"github.com/suyashkumar/ssl-proxy/reverseproxy"
)

type Route struct {
	Host   string `json:"host"`
	Path   string `json:"path"`
	Target string `json:"target"`
}

var (
	to           = flag.String("to", "http://127.0.0.1:80", "the address and port for which to proxy requests to")
	fromURL      = flag.String("from", "127.0.0.1:4430", "the tcp address and port this proxy should listen for requests on")
	certFile     = flag.String("cert", "cert.pem", "path to a tls certificate file")
	keyFile      = flag.String("key", "key.pem", "path to a private key file")
	domain       = flag.String("domain", "", "domain to mint letsencrypt certificates for")
	redirectHTTP = flag.Bool("redirectHTTP", false, "if true, redirects http requests from port 80 to https at your fromURL")
	routers      = flag.String("routers", "", "Routing rules in the form /path=target or host=/path=target")
	routersFile  = flag.String("routersFile", "", "JSON string or file path for routing rules")
	root         = flag.String("root", "", "Serve static files from this directory")
	certOrg      = flag.String("certOrg", "ssl-proxy", "Organization for generated certificate")
	certDNS      = flag.String("certDNS", "localhost", "Comma-separated DNS names")
	certIP       = flag.String("certIP", "", "Comma-separated IPs")
	daemon       = flag.Bool("daemon", false, "Run as a background daemon process")
)

func main() {
	flag.Parse()

	if *daemon {
		runAsDaemon()
	}

	validCertFile := *certFile != ""
	validKeyFile := *keyFile != ""

	if (!validCertFile || !fileExists(*certFile)) || (!validKeyFile || !fileExists(*keyFile)) {
		*certFile = "cert.pem"
		*keyFile = "key.pem"
		log.Printf("Generating self-signed certs (%s, %s)\n", *certFile, *keyFile)
		certBuf, keyBuf, _, err := gen.Keys(365*24*time.Hour, *certOrg, strings.Split(*certDNS, ","), parseIPList(*certIP))
		if err != nil {
			log.Fatal("Error generating keys: ", err)
		}
		os.WriteFile(*certFile, certBuf.Bytes(), 0644)
		os.WriteFile(*keyFile, keyBuf.Bytes(), 0600)
	}

	var routesList []Route
	if *routers != "" {
		routesList, _ = parseRouters(*routers)
	} else if *routersFile != "" {
		routesList, _ = loadRoutersFile(*routersFile)
	}

	multiListenerRoutes := groupRoutesByListener(routesList)
	if len(multiListenerRoutes) > 0 {
		for addr, routeGroup := range multiListenerRoutes {
			go func(addr string, routes []Route) {
				mux := http.NewServeMux()
				toURL, _ := url.Parse(routes[0].Target)
				proxy := reverseproxy.Build(toURL)
				mux.HandleFunc("/", routeHandler(routes, proxy))
				log.Printf(green("Listening on %s"), addr)
				http.ListenAndServeTLS(addr, *certFile, *keyFile, mux)
			}(addr, routeGroup)
		}
		select {} // block forever
	}

	mux := http.NewServeMux()
	toURL, _ := url.Parse(*to)
	proxy := reverseproxy.Build(toURL)
	mux.HandleFunc("/", routeHandler(routesList, proxy))
	log.Fatal(http.ListenAndServeTLS(*fromURL, *certFile, *keyFile, mux))
}

func loadRoutersFile(arg string) ([]Route, error) {
	var data []byte
	var err error
	if strings.HasSuffix(arg, ".json") {
		data, err = os.ReadFile(arg)
	} else {
		data = []byte(arg)
	}
	if err != nil {
		return nil, err
	}
	var routes []Route
	err = json.Unmarshal(data, &routes)
	return routes, err
}

func parseRouters(routersArg string) ([]Route, error) {
	var routes []Route
	items := strings.Split(routersArg, ",")
	for _, item := range items {
		item = strings.TrimSpace(item)
		left, right, found := strings.Cut(item, "=")
		if !found {
			continue
		}
		target := right
		var host, path string
		if strings.HasPrefix(left, "/") {
			path = left
		} else if strings.Contains(left, "/") {
			parts := strings.SplitN(left, "/", 2)
			host = parts[0]
			path = "/" + parts[1]
		} else {
			host = left
		}
		routes = append(routes, Route{Host: host, Path: path, Target: target})
	}
	return routes, nil
}

func routeHandler(routes []Route, defaultProxy http.Handler) http.HandlerFunc {
	proxies := map[string]http.Handler{}
	for _, r := range routes {
		u, _ := url.Parse(r.Target)
		proxies[r.Host+"|"+r.Path] = reverseproxy.Build(u)
	}
	return func(w http.ResponseWriter, req *http.Request) {
		host := req.Host
		path := req.URL.Path
		for _, r := range routes {
			if r.Host != "" && r.Path != "" && host == r.Host && strings.HasPrefix(path, r.Path) {
				proxies[r.Host+"|"+r.Path].ServeHTTP(w, req)
				return
			}
		}
		if defaultProxy != nil {
			defaultProxy.ServeHTTP(w, req)
		} else {
			http.NotFound(w, req)
		}
	}
}

func groupRoutesByListener(routes []Route) map[string][]Route {
	routeMap := make(map[string][]Route)
	for _, r := range routes {
		if r.Host == "" || !strings.Contains(r.Host, ":") {
			continue
		}
		routeMap[r.Host] = append(routeMap[r.Host], r)
	}
	return routeMap
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	return err == nil && !info.IsDir()
}

func parseIPList(ipStr string) []net.IP {
	if ipStr == "" {
		return nil
	}
	parts := strings.Split(ipStr, ",")
	var ips []net.IP
	for _, p := range parts {
		ip := net.ParseIP(strings.TrimSpace(p))
		if ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips
}

func green(in string) string {
	return fmt.Sprintf("\033[0;32m%s\033[0;0m", in)
}

func runAsDaemon() {
	execPath, err := os.Executable()
	if err != nil {
		log.Fatalf("Failed to get executable path: %v", err)
	}

	args := os.Args[1:]
	var newArgs []string
	for i := 0; i < len(args); i++ {
		if args[i] == "-daemon" || strings.HasPrefix(args[i], "-daemon=") {
			continue
		}
		newArgs = append(newArgs, args[i])
	}

	cmd := exec.Command(execPath, newArgs...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.Stdin = nil

	logFile, err := os.OpenFile("ssl-proxy.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err == nil {
		cmd.Stdout = logFile
		cmd.Stderr = logFile
	} else {
		log.Printf("Warning: Cannot open log file, continue without redirection: %v", err)
	}

	err = cmd.Start()
	if err != nil {
		log.Fatalf("Failed to start daemon: %v", err)
	}
	log.Printf("Started daemon process (pid=%d), exiting parent.\n", cmd.Process.Pid)
	os.Exit(0)
}
