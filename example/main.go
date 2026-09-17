// Command example demonstrates using the proxyauth Transport to fetch a URL
// through an authenticating corporate proxy.
//
//	# Uses HTTPS_PROXY / HTTP_PROXY / NO_PROXY from the environment,
//	# authenticating as the logged-in Windows user:
//	set HTTPS_PROXY=http://proxy.corp.example:8080
//	go run . https://internal.example.com/health
//
//	# Or point at a proxy explicitly:
//	go run . -proxy http://proxy.corp.example:8080 https://internal.example.com/health
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/sanjaynagpal/proxyauth"
)

func main() {
	proxyFlag := flag.String("proxy", "", "proxy URL (default: from environment)")
	spnFlag := flag.String("spn", "", "override the SPN (default: HTTP/<proxy-host>)")
	user := flag.String("user", "", "explicit username (default: logged-in user / SSO)")
	domain := flag.String("domain", "", "domain for explicit credentials")
	pass := flag.String("pass", "", "password for explicit credentials")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: example [flags] <url>")
		flag.PrintDefaults()
		os.Exit(2)
	}
	target := flag.Arg(0)

	cfg := proxyauth.Config{
		SPN:      *spnFlag,
		Username: *user,
		Domain:   *domain,
		Password: *pass,
	}
	if *proxyFlag != "" {
		u, err := url.Parse(*proxyFlag)
		if err != nil {
			log.Fatalf("bad -proxy: %v", err)
		}
		cfg.ProxyURL = u
	}

	client := &http.Client{
		Transport: proxyauth.New(cfg),
		Timeout:   30 * time.Second,
	}

	resp, err := client.Get(target)
	if err != nil {
		log.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	fmt.Printf("%s\n\n%s\n", resp.Status, body)
}
