// Command enumerator runs the network enumerator: a background scanner that
// discovers subnets, hosts, and open ports, plus a web UI that shows results
// live. Everything lives in a single static binary with an in-memory
// SQLite database and an embedded frontend, so it can be dropped onto a
// bare host or into an air-gapped Docker container and just run.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"network-enumerator/internal/api"
	"network-enumerator/internal/discovery"
	"network-enumerator/internal/model"
	"network-enumerator/internal/store"
	"network-enumerator/web"
)

func main() {
	defCfg := discovery.DefaultConfig()

	// CLI flags let the tool be configured with a switch when run locally
	// (e.g. ./enumerator -p 8080) instead of only via env vars. Env vars
	// still win when both are set — that's checked below, flag by flag —
	// since they're how the Docker/air-gapped deployment is configured and
	// shouldn't be silently overridden by a leftover local flag.
	var port string
	flag.StringVar(&port, "port", "8080", "HTTP port to listen on")
	flag.StringVar(&port, "p", "8080", "shorthand for -port")
	scanInterval := flag.Int("scan-interval", int(defCfg.Interval.Seconds()), "seconds between scan cycles")
	hostConcurrency := flag.Int("host-concurrency", defCfg.HostConcurrency, "max hosts probed concurrently per subnet")
	portConcurrency := flag.Int("port-concurrency", defCfg.PortConcurrency, "max ports probed concurrently per host")
	missThreshold := flag.Int("miss-threshold", defCfg.MissThreshold, "consecutive missed scans before a host is marked down")
	autoDiscoverLocal := flag.Bool("auto-discover-local", defCfg.AutoDiscoverLocal, "automatically scan subnets attached to local interfaces")
	maxHostsPerSubnet := flag.Int("max-hosts-per-subnet", discovery.MaxHostsPerSubnet, "cap on addresses expanded per subnet")
	dbFile := flag.String("db-file", "", "path to a SQLite file to persist data across restarts (default: in-memory, nothing persisted)")
	// The Settings UI for changing the admin password is hidden for now, so
	// this flag (and $ADMIN_PASSWORD) is the only way to set it to something
	// other than the built-in default on a fresh database.
	adminPassword := flag.String("password", "", "set the initial admin password on first run, instead of the built-in default (ignored if the database already has credentials)")
	flag.Parse()

	addr := ":" + envOr("PORT", port)
	dbPath := envOr("DB_FILE", *dbFile)
	initialPassword := envOr("ADMIN_PASSWORD", *adminPassword)

	cfg := discovery.DefaultConfig()
	cfg.Interval = time.Duration(envInt("SCAN_INTERVAL_SECONDS", *scanInterval)) * time.Second
	cfg.HostConcurrency = envInt("HOST_CONCURRENCY", *hostConcurrency)
	cfg.PortConcurrency = envInt("PORT_CONCURRENCY", *portConcurrency)
	cfg.MissThreshold = envInt("MISS_THRESHOLD", *missThreshold)
	cfg.AutoDiscoverLocal = envOr("AUTO_DISCOVER_LOCAL", strconv.FormatBool(*autoDiscoverLocal)) != "false"
	discovery.MaxHostsPerSubnet = envInt("MAX_HOSTS_PER_SUBNET", *maxHostsPerSubnet)

	st, err := store.Open(dbPath, initialPassword)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer st.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	hub := api.NewHub()
	scanner := discovery.NewScanner(st, cfg, func(ev model.Event) { hub.Broadcast(ev) })
	defer scanner.Close()

	// Start scanning immediately rather than waiting on the startup banner's
	// countdown below — that countdown exists purely so someone parachuting
	// this onto an unfamiliar box has time to read the config/credentials
	// summary before request logs start scrolling under it. There's no
	// reason actual discovery should sit idle for it too; subnets get
	// identified and scanning begins in the background while the banner is
	// still counting down.
	go scanner.Run(ctx)

	if !printStartupBanner(ctx, addr, dbPath, cfg, st.UsingDefaultCredentials()) {
		return // interrupted during the countdown, e.g. Ctrl-C
	}

	mux := http.NewServeMux()
	api.New(st, scanner, hub).Routes(mux)
	mux.Handle("/", web.Handler())

	srv := &http.Server{
		Addr:              addr,
		Handler:           logRequests(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Printf("network-enumerator listening on %s (scan interval %s)", addr, cfg.Interval)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}

// logRequests logs API calls to the command line: mutating requests always,
// GETs only when they error, and it skips the static assets and the SSE
// stream entirely so routine polling doesn't drown out real activity.
func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/static/") || r.URL.Path == "/api/events/stream" {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		if r.Method != http.MethodGet || sw.status >= 400 {
			log.Printf("%s %s -> %d (%s)", r.Method, r.URL.Path, sw.status, time.Since(start).Round(time.Millisecond))
		}
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

// startupCountdown is how long the config/credentials summary stays on
// screen before the server actually starts listening. Long enough for
// someone parachuting this onto an unfamiliar box to actually read it before
// request logs start scrolling past underneath it.
const startupCountdown = 10 * time.Second

// printStartupBanner logs the effective configuration and, if the account
// still has the out-of-the-box credentials, a reminder to change them —
// then holds for startupCountdown so both are visible before the request
// log starts scrolling. Returns false if ctx was cancelled during the
// countdown (e.g. Ctrl-C), in which case the caller should exit immediately
// rather than go on to start the server.
func printStartupBanner(ctx context.Context, addr, dbPath string, cfg discovery.Config, usingDefaultCreds bool) bool {
	log.Printf("network-enumerator starting — listen %s, scan interval %s, host concurrency %d, port concurrency %d, miss threshold %d, auto-discover local subnets %t",
		addr, cfg.Interval, cfg.HostConcurrency, cfg.PortConcurrency, cfg.MissThreshold, cfg.AutoDiscoverLocal)
	if nmapPath, ok := discovery.NmapPath(); ok {
		log.Printf("nmap found at %s — used for scanning when the scan method is set to auto or nmap", nmapPath)
	} else {
		log.Printf("nmap not found on PATH — using built-in TCP/ICMP scanning (install nmap and it'll be used automatically)")
	}
	if dbPath != "" {
		log.Printf("persisting data to %s", dbPath)
	} else {
		log.Printf("using in-memory database; data will not survive a restart (set -db-file to persist)")
	}
	if usingDefaultCreds {
		log.Printf("login is still set to the built-in default credentials — restart with -password (or $ADMIN_PASSWORD) to set a real one")
	}

	// A redirected/piped log (Docker, a file, `| tee`) can't usefully rewrite
	// a line in place — each "\r" would just land as another line in the
	// output — so there it's one message instead of a per-second countdown.
	if !isTerminal(os.Stdout) {
		log.Printf("starting in %d seconds...", int(startupCountdown.Seconds()))
		select {
		case <-time.After(startupCountdown):
		case <-ctx.Done():
			log.Printf("startup interrupted")
			return false
		}
		return true
	}

	for remaining := int(startupCountdown.Seconds()); remaining > 0; remaining-- {
		fmt.Fprintf(os.Stdout, "\rstarting in %ds…   ", remaining)
		select {
		case <-time.After(time.Second):
		case <-ctx.Done():
			fmt.Fprintln(os.Stdout)
			log.Printf("startup interrupted")
			return false
		}
	}
	fmt.Fprint(os.Stdout, "\r")
	return true
}

// isTerminal reports whether f looks like an interactive terminal rather
// than a pipe, redirected file, or Docker's log collector — the cases where
// overwriting a line with "\r" wouldn't render as intended.
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}
