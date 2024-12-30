package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// Query represents a DNS query with a domain and type.
type Query struct {
	Domain string
	Type   uint16
}

func main() {
	// Define flags for input file, upstream DNS server, protocol, and socket path.
	filePath := flag.String("file", "queries.txt", "Path to the file containing DNS queries")
	upstream := flag.String("upstream", "8.8.8.8:53", "Upstream DNS server")
	protocol := flag.String("protocol", "udp", "Protocol to use for DNS queries (udp/tcp/socket)")
	socketPath := flag.String("socket", "/tmp/dns_server.sock", "Path to the UNIX socket")
	flag.Parse()

	// Validate protocol.
	if *protocol != "udp" && *protocol != "tcp" && *protocol != "socket" {
		log.Fatalf("unsupported protocol: %s", *protocol)
	}

	// Open the file containing domain names and query types.
	file, err := os.Open(*filePath)
	if err != nil {
		log.Fatalf("failed to open file: %v", err)
	}
	defer file.Close()

	// Read the queries from the file.
	// Read the queries from the file.
	var queries []Query
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) == 0 {
			log.Printf("skipping empty line")
			continue
		}
		var qType uint16
		if len(fields) == 1 {
			qType = dns.TypeA // Default to A record if only the domain is provided.
		} else if len(fields) == 2 {
			var err error
			qType, err = parseQueryType(fields[1])
			if err != nil {
				log.Printf("skipping invalid query type: %s", fields[1])
				continue
			}
		} else {
			log.Printf("skipping invalid line: %s", line)
			continue
		}
		queries = append(queries, Query{Domain: fields[0], Type: qType})
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("error reading file: %v", err)
	}

	// Set up counters.
	var totalQueries int64
	var successfulQueries int64
	var timeoutQueries int64

	// Measure execution time.
	startTime := time.Now()

	// Set up a WaitGroup to manage goroutines.
	var wg sync.WaitGroup
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Limit the number of concurrent queries.
	sem := make(chan struct{}, 1000) // Limit to 100 concurrent queries.

	for _, query := range queries {
		wg.Add(1)
		sem <- struct{}{} // Acquire semaphore.
		atomic.AddInt64(&totalQueries, 1)
		go func(q Query) {
			defer wg.Done()
			defer func() { <-sem }() // Release semaphore.

			// Send query to both upstream and socket if both are specified.
			if *protocol == "socket" {
				if *upstream != "" {
					go func() {
						if err := performDNSQuery(ctx, q, *upstream, "udp", &successfulQueries, &timeoutQueries); err != nil {
							log.Printf("upstream query failed: %v", err)
						}
					}()
				}
				processUnixSocket(*socketPath, q, &successfulQueries, &timeoutQueries)
			} else {
				if err := performDNSQuery(ctx, q, *upstream, *protocol, &successfulQueries, &timeoutQueries); err != nil {
					log.Printf("query failed: %v", err)
				}
			}
		}(query)
	}

	// Wait for all goroutines to complete.
	wg.Wait()
	totalTime := time.Since(startTime)
	log.Printf("All queries completed in %v. Total: %d, Successful: %d, Timeouts: %d", totalTime, totalQueries, successfulQueries, timeoutQueries)
}

// processUnixSocket sends a DNS query and processes the response using a UNIX socket.
func processUnixSocket(socketPath string, query Query, successfulQueries, timeoutQueries *int64) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		log.Printf("Failed to connect to Unix socket: %v", err)
		atomic.AddInt64(timeoutQueries, 1)
		return
	}
	defer conn.Close()

	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn(query.Domain), query.Type)
	msg.RecursionDesired = true

	data, err := msg.Pack()
	if err != nil {
		log.Printf("Failed to pack DNS message: %v", err)
		atomic.AddInt64(timeoutQueries, 1)
		return
	}

	if _, err := conn.Write(data); err != nil {
		log.Printf("Failed to write to Unix socket: %v", err)
		atomic.AddInt64(timeoutQueries, 1)
		return
	}

	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		log.Printf("Failed to read from Unix socket: %v", err)
		atomic.AddInt64(timeoutQueries, 1)
		return
	}

	resp := &dns.Msg{}
	if err := resp.Unpack(buf[:n]); err != nil {
		log.Printf("Failed to unpack DNS response: %v", err)
		atomic.AddInt64(timeoutQueries, 1)
		return
	}

	atomic.AddInt64(successfulQueries, 1)
	log.Printf("Socket response for %s: %v", query.Domain, resp)
}

// SetEDNSOptions - Set EDNS options
func SetEDNSOptions(m *dns.Msg, size uint16, do bool) {
	edns := new(dns.OPT)
	edns.Hdr.Name = "."
	edns.Hdr.Rrtype = dns.TypeOPT
	edns.SetUDPSize(size)
	edns.SetDo(do)
	m.Extra = append(m.Extra, edns)
}

// performDNSQuery sends a DNS query and logs the response or error.
func performDNSQuery(ctx context.Context, query Query, upstream, protocol string, successfulQueries, timeoutQueries *int64) error {
	var client *dns.Client
	if protocol == "socket" {
		client = &dns.Client{
			Net: "unix",
		}
	} else {
		client = &dns.Client{
			Net: protocol, // Specify the protocol (udp/tcp).
		}
	}

	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn(query.Domain), query.Type)
	msg.RecursionDesired = true
	SetEDNSOptions(msg, 4096, true)

	// Send the DNS query.
	resp, _, err := client.ExchangeContext(ctx, msg, upstream)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			atomic.AddInt64(timeoutQueries, 1)
		} else {
			log.Printf("error performing query: %v", err)
		}
		return fmt.Errorf("failed to perform query: %w", err)
	}

	// Log the response.
	atomic.AddInt64(successfulQueries, 1)
	log.Printf("response for %s: %v", query.Domain, resp)
	return nil
}

// parseQueryType converts a string type to a dns.Type.
func parseQueryType(qType string) (uint16, error) {
	switch strings.ToUpper(qType) {
	case "A":
		return dns.TypeA, nil
	case "AAAA":
		return dns.TypeAAAA, nil
	case "PTR":
		return dns.TypePTR, nil
	default:
		return 0, fmt.Errorf("unsupported query type: %s", qType)
	}
}
