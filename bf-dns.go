package main

// Imports
import (
	"os"
	"fmt"
	"net"
	"sync"
	"time"
	"strings"
	"io/ioutil"
	"encoding/json"
	"gopkg.in/yaml.v1"
	"github.com/miekg/dns"
)

// Hold the global log file
var logEncoder *json.Encoder

// Define the format of the config file
type ConfigStruct struct {
	Binds []struct {
		Address string
		Port string
	}
	Log string
	Control string
	Contact string
	Questions map[string][]string
	Answers struct {
		Flipped struct {
			A string
			AAAA string
		}
		Correct struct {
			A string
			AAAA string
		}
	}
}

// Config will hold the actual config instance
var Config = ConfigStruct{}

// Map of flipped domain to correct domain
var flippedDomains = make(map[string]string)

// Makes a reply msg given a request
func createReply(req *dns.Msg) *dns.Msg {

	// Create a response/reply msg
	m := new(dns.Msg)
	m.SetReply(req)

	// Save our precious bandwidth if possible
	m.Compress = true

	// Add a disclaimer extra to every response
	m.Extra = make([]dns.RR, 1)
	m.Extra[0] = &dns.TXT{
		Hdr: dns.RR_Header{
			Name: m.Question[0].Name,
			Rrtype: dns.TypeTXT,
			Class: dns.ClassINET,
			Ttl: 604800,
		},
		Txt: []string{"This server is part of an InfoSec project. You can find more information on " + Config.Control},
	}

	// Return it
	return m

}

// Define the format of a log
type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Type uint8 `json:"type"`
	Destination string `json:"dst"`
	Source string `json:"src"`
	Port string `json:"port"`
	QName string `json:"qName"`
	QType uint16 `json:"qType"`
	QClass uint16 `json:"qClass"`
}

// Logs the query to the log file
func logQuestion(w dns.ResponseWriter, req *dns.Msg, queryType uint8) {

	// Grab the local address info
	localAddress, _, err := net.SplitHostPort(w.LocalAddr().String())
	if err != nil {
		panic(err)
	}
	remoteAddress, remotePort, err := net.SplitHostPort(w.RemoteAddr().String())
	if err != nil {
		panic(err)
	}

	// Make a new LogEntry
	log := LogEntry{
		Timestamp: time.Now().Format("2006-01-02T15:04:05"),
		Type: queryType,
		Destination: localAddress,
		Source: remoteAddress,
		Port: remotePort,
		QName: req.Question[0].Name,
		QType: req.Question[0].Qtype,
		QClass: req.Question[0].Qclass,
	}
	
	// Log it as JSON
	err = logEncoder.Encode(log)
	if err != nil {
		panic(err)
	}

}

// Answers flipped requests
func FlipServer(w dns.ResponseWriter, req *dns.Msg) {

	// Attempt to log the request to the control domain
	logQuestion(w, req, 3)

	// Create a response/reply msg
	m1 := createReply(req)

	// Make a reply
	if m1.Question[0].Qclass == 1 {
		if m1.Question[0].Qtype == 1 {
			m1.Answer = []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{
						Name: m1.Question[0].Name,
						Rrtype: dns.TypeA,
						Class: dns.ClassINET,
						Ttl: 1,
					},
					A: net.ParseIP(Config.Answers.Flipped.A),
				},
			}
		} else if m1.Question[0].Qtype == 2 {
			m1.Answer = []dns.RR{
				&dns.NS{
					Hdr: dns.RR_Header{
						Name: m1.Question[0].Name,
						Rrtype: dns.TypeNS,
						Class: dns.ClassINET,
						Ttl: 604800,
					},
					Ns: "ns1." + Config.Control + ".",
				},
				&dns.NS{
					Hdr: dns.RR_Header{
						Name: m1.Question[0].Name,
						Rrtype: dns.TypeNS,
						Class: dns.ClassINET,
						Ttl: 604800,
					},
					Ns: "ns2." + Config.Control + ".",
				},
			}
		} else if m1.Question[0].Qtype == 6 {
			m1.Answer = []dns.RR{
				&dns.SOA{
					Hdr: dns.RR_Header{
						Name: m1.Question[0].Name,
						Rrtype: dns.TypeSOA,
						Class: dns.ClassINET,
						Ttl: 604800,
					},
					Ns: "ns1." + Config.Control + ".",
					Mbox: Config.Contact + ".",
					Serial: 1,
					Refresh: 28800,
					Retry: 7200,
					Expire: 604800,
					Minttl: 60,
				},
			}
		} else if m1.Question[0].Qtype == 15 {
			m1.Answer = []dns.RR{
				&dns.MX{
					Hdr: dns.RR_Header{
						Name: m1.Question[0].Name,
						Rrtype: dns.TypeMX,
						Class: dns.ClassINET,
						Ttl: 604800,
					},
					Preference: 1,
					Mx: "mx." + Config.Control + ".",
				},
			}
		} else if m1.Question[0].Qtype == 28 {
			m1.Answer = []dns.RR{
				&dns.AAAA{
					Hdr: dns.RR_Header{
						Name: m1.Question[0].Name,
						Rrtype: dns.TypeAAAA,
						Class: dns.ClassINET,
						Ttl: 1,
					},
					AAAA: net.ParseIP(Config.Answers.Flipped.AAAA[1:len(Config.Answers.Flipped.AAAA)-1]),
				},
			}
		}
	}

	// Send the flipped response back
	w.WriteMsg(m1)

	// Create a second response/reply msg
	m2 := createReply(req)

	// Grab the request
	host_parts := strings.Split(m2.Question[0].Name, ".")

	// Replace the domain with the correct value
	host_parts[len(host_parts) - 3] = flippedDomains[strings.Join(host_parts[len(host_parts) - 3:len(host_parts) - 1], ".")]

	// Replace the question with the correct value
	m2.Question[0].Name = strings.Join(host_parts, ".")

	// Make a reply
	if m2.Question[0].Qclass == 1 {
		if m2.Question[0].Qtype == 1 {
			m2.Answer = []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{
						Name: m2.Question[0].Name,
						Rrtype: dns.TypeA,
						Class: dns.ClassINET,
						Ttl: 1,
					},
					A: net.ParseIP(Config.Answers.Flipped.A),
				},
			}
		} else if m2.Question[0].Qtype == 2 {
			m2.Answer = []dns.RR{
				&dns.NS{
					Hdr: dns.RR_Header{
						Name: m2.Question[0].Name,
						Rrtype: dns.TypeNS,
						Class: dns.ClassINET,
						Ttl: 604800,
					},
					Ns: "ns1." + Config.Control + ".",
				},
				&dns.NS{
					Hdr: dns.RR_Header{
						Name: m2.Question[0].Name,
						Rrtype: dns.TypeNS,
						Class: dns.ClassINET,
						Ttl: 604800,
					},
					Ns: "ns2." + Config.Control + ".",
				},
			}
		} else if m2.Question[0].Qtype == 6 {
			m2.Answer = []dns.RR{
				&dns.SOA{
					Hdr: dns.RR_Header{
						Name: m2.Question[0].Name,
						Rrtype: dns.TypeSOA,
						Class: dns.ClassINET,
						Ttl: 604800,
					},
					Ns: "ns1." + Config.Control + ".",
					Mbox: Config.Contact + ".",
					Serial: 1,
					Refresh: 28800,
					Retry: 7200,
					Expire: 604800,
					Minttl: 60,
				},
			}
		} else if m2.Question[0].Qtype == 15 {
			m2.Answer = []dns.RR{
				&dns.MX{
					Hdr: dns.RR_Header{
						Name: m2.Question[0].Name,
						Rrtype: dns.TypeMX,
						Class: dns.ClassINET,
						Ttl: 604800,
					},
					Preference: 1,
					Mx: "mx." + Config.Control + ".",
				},
			}
		} else if m2.Question[0].Qtype == 28 {
			m2.Answer = []dns.RR{
				&dns.AAAA{
					Hdr: dns.RR_Header{
						Name: m2.Question[0].Name,
						Rrtype: dns.TypeAAAA,
						Class: dns.ClassINET,
						Ttl: 1,
					},
					AAAA: net.ParseIP(Config.Answers.Correct.AAAA[1:len(Config.Answers.Correct.AAAA)-1]),
				},
			}
		}
	}

	// Change the question to the 'correct' domain
	w.WriteMsg(m2)

}

// Answers control domain requests
func ControlServer(w dns.ResponseWriter, req *dns.Msg) {

	// Attempt to log the request to the control domain
	logQuestion(w, req, 1)

	// Create a response/reply msg
	m := createReply(req)

	// Make a reply
	if m.Question[0].Qclass == 1 {
		if m.Question[0].Qtype == 1 {
			m.Answer = []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{
						Name: m.Question[0].Name,
						Rrtype: dns.TypeA,
						Class: dns.ClassINET,
						Ttl: 604800,
					},
					A: net.ParseIP(Config.Answers.Correct.A),
				},
				&dns.A{
					Hdr: dns.RR_Header{
						Name: m.Question[0].Name,
						Rrtype: dns.TypeA,
						Class: dns.ClassINET,
						Ttl: 604800,
					},
					A: net.ParseIP(Config.Answers.Flipped.A),
				},
			}
			m.Ns = []dns.RR{
				&dns.NS{
					Hdr: dns.RR_Header{
						Name: m.Question[0].Name,
						Rrtype: dns.TypeNS,
						Class: dns.ClassINET,
						Ttl: 604800,
					},
					Ns: "ns1." + Config.Control + ".",
				},
				&dns.NS{
					Hdr: dns.RR_Header{
						Name: m.Question[0].Name,
						Rrtype: dns.TypeNS,
						Class: dns.ClassINET,
						Ttl: 604800,
					},
					Ns: "ns2." + Config.Control + ".",
				},
			}
		} else if m.Question[0].Qtype == 2 {
			m.Answer = []dns.RR{
				&dns.NS{
					Hdr: dns.RR_Header{
						Name: m.Question[0].Name,
						Rrtype: dns.TypeNS,
						Class: dns.ClassINET,
						Ttl: 604800,
					},
					Ns: "ns1." + Config.Control + ".",
				},
				&dns.NS{
					Hdr: dns.RR_Header{
						Name: m.Question[0].Name,
						Rrtype: dns.TypeNS,
						Class: dns.ClassINET,
						Ttl: 604800,
					},
					Ns: "ns2." + Config.Control + ".",
				},
			}
		} else if m.Question[0].Qtype == 6 {
			m.Answer = []dns.RR{
				&dns.SOA{
					Hdr: dns.RR_Header{
						Name: m.Question[0].Name,
						Rrtype: dns.TypeSOA,
						Class: dns.ClassINET,
						Ttl: 604800,
					},
					Ns: "ns1." + Config.Control + ".",
					Mbox: Config.Contact + ".",
					Serial: 1,
					Refresh: 28800,
					Retry: 7200,
					Expire: 604800,
					Minttl: 60,
				},
			}
		} else if m.Question[0].Qtype == 15 {
			m.Answer = []dns.RR{
				&dns.MX{
					Hdr: dns.RR_Header{
						Name: m.Question[0].Name,
						Rrtype: dns.TypeMX,
						Class: dns.ClassINET,
						Ttl: 604800,
					},
					Preference: 1,
					Mx: "mx." + Config.Control + ".",
				},
			}
		} else if m.Question[0].Qtype == 28 {
			m.Answer = []dns.RR{
				&dns.AAAA{
					Hdr: dns.RR_Header{
						Name: m.Question[0].Name,
						Rrtype: dns.TypeAAAA,
						Class: dns.ClassINET,
						Ttl: 604800,
					},
					AAAA: net.ParseIP(Config.Answers.Correct.AAAA[1:len(Config.Answers.Correct.AAAA)-1]),
				},
				&dns.AAAA{
					Hdr: dns.RR_Header{
						Name: m.Question[0].Name,
						Rrtype: dns.TypeAAAA,
						Class: dns.ClassINET,
						Ttl: 604800,
					},
					AAAA: net.ParseIP(Config.Answers.Flipped.AAAA[1:len(Config.Answers.Flipped.AAAA)-1]),
				},
			}
			m.Ns = []dns.RR{
				&dns.NS{
					Hdr: dns.RR_Header{
						Name: m.Question[0].Name,
						Rrtype: dns.TypeNS,
						Class: dns.ClassINET,
						Ttl: 604800,
					},
					Ns: "ns1." + Config.Control + ".",
				},
				&dns.NS{
					Hdr: dns.RR_Header{
						Name: m.Question[0].Name,
						Rrtype: dns.TypeNS,
						Class: dns.ClassINET,
						Ttl: 604800,
					},
					Ns: "ns2." + Config.Control + ".",
				},
			}
		}
	}

	// Send back a normal response
	w.WriteMsg(m)

}

// Answers unflipped domain requests
func UnflippedServer(w dns.ResponseWriter, req *dns.Msg) {

	// Attempt to log the request to the control domain
	logQuestion(w, req, 2)

	// Create a response/reply msg
	m := createReply(req)

	// Make a reply
	if m.Question[0].Qclass == 1 {
		if m.Question[0].Qtype == 1 {
			m.Answer = []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{
						Name: m.Question[0].Name,
						Rrtype: dns.TypeA,
						Class: dns.ClassINET,
						Ttl: 1,
					},
					A: net.ParseIP(Config.Answers.Correct.A),
				},
				&dns.A{
					Hdr: dns.RR_Header{
						Name: m.Question[0].Name,
						Rrtype: dns.TypeA,
						Class: dns.ClassINET,
						Ttl: 1,
					},
					A: net.ParseIP(Config.Answers.Flipped.A),
				},
			}
		} else if m.Question[0].Qtype == 2 {
			m.Answer = []dns.RR{
				&dns.NS{
					Hdr: dns.RR_Header{
						Name: m.Question[0].Name,
						Rrtype: dns.TypeNS,
						Class: dns.ClassINET,
						Ttl: 604800,
					},
					Ns: "ns1." + Config.Control + ".",
				},
				&dns.NS{
					Hdr: dns.RR_Header{
						Name: m.Question[0].Name,
						Rrtype: dns.TypeNS,
						Class: dns.ClassINET,
						Ttl: 604800,
					},
					Ns: "ns2." + Config.Control + ".",
				},
			}
		} else if m.Question[0].Qtype == 6 {
			m.Answer = []dns.RR{
				&dns.SOA{
					Hdr: dns.RR_Header{
						Name: m.Question[0].Name,
						Rrtype: dns.TypeSOA,
						Class: dns.ClassINET,
						Ttl: 604800,
					},
					Ns: "ns1." + Config.Control + ".",
					Mbox: Config.Contact + ".",
					Serial: 1,
					Refresh: 28800,
					Retry: 7200,
					Expire: 604800,
					Minttl: 60,
				},
			}
		} else if m.Question[0].Qtype == 15 {
			m.Answer = []dns.RR{
				&dns.MX{
					Hdr: dns.RR_Header{
						Name: m.Question[0].Name,
						Rrtype: dns.TypeMX,
						Class: dns.ClassINET,
						Ttl: 1,
					},
					Preference: 1,
					Mx: "mx." + Config.Control + ".",
				},
			}
		} else if m.Question[0].Qtype == 28 {
			m.Answer = []dns.RR{
				&dns.AAAA{
					Hdr: dns.RR_Header{
						Name: m.Question[0].Name,
						Rrtype: dns.TypeAAAA,
						Class: dns.ClassINET,
						Ttl: 1,
					},
					AAAA: net.ParseIP(Config.Answers.Correct.AAAA[1:len(Config.Answers.Correct.AAAA)-1]),
				},
				&dns.AAAA{
					Hdr: dns.RR_Header{
						Name: m.Question[0].Name,
						Rrtype: dns.TypeAAAA,
						Class: dns.ClassINET,
						Ttl: 1,
					},
					AAAA: net.ParseIP(Config.Answers.Flipped.AAAA[1:len(Config.Answers.Flipped.AAAA)-1]),
				},
			}
		}
	}

	// Send back a normal response
	w.WriteMsg(m)

}

// Answers unknown domain requests
func UnknownServer(w dns.ResponseWriter, req *dns.Msg) {

	// Attempt to log the request to an unknown domain
	logQuestion(w, req, 0)

	// Create a response/reply msg
	m := createReply(req)

	// Refuse it since we don't know how to handle it
	m.Rcode = 5

	// Send back the answer 
	w.WriteMsg(m)

}

// Spawns a listening server given the bind info
func startListening(mux *dns.ServeMux, address string, port string) {

	// Create a dns server
	server := &dns.Server{
		Addr: address + ":" + port,
		Net: "udp",
		Handler: mux,
	}

	// Begin listening and serving requests
	err := server.ListenAndServe()
	if err != nil {
		panic(err)
	}

}

// Entry Point
func main() {

	// If not enough args were provided, print usage to stderr and bail
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s: [configFile]\n", os.Args[0])
		os.Exit(1)
	}

	// Try to read in the passed config file to a byte array
	configFile, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}

	// Parse the passed in yaml config
	err = yaml.Unmarshal(configFile, &Config)
	if err != nil {
		panic(err)
	}

	// Update the contact email
	Config.Contact = strings.Replace(Config.Contact, "@", ".", -1)

	// Open the log file specified in the Config
	logFile, err := os.OpenFile(Config.Log, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600);
	if err != nil {
		panic(err)
	}
	defer logFile.Close()

	// Create an encoder
	logEncoder = json.NewEncoder(logFile)

	// Create a ServeMux instance
	mux := dns.NewServeMux()

	// Set the default handler to UnknownServer
	mux.HandleFunc(".", UnknownServer)

	// Add the control domain handler
	mux.HandleFunc(Config.Control, ControlServer)

	// Loop each question
	for correct, flips := range Config.Questions {

		// Add the unflipped domain handler
		mux.HandleFunc(correct, UnflippedServer)

		// Loop each possible flip
		for _, flip := range flips {

			// Save the correlation in flippedDomains
			flippedDomains[flip] = strings.Split(correct, ".")[0]

			// Add a flipped handler to the mux
			mux.HandleFunc(flip, FlipServer)

		}

	}

	// Each listener will be spawned in a new goroutine
	var wg sync.WaitGroup

	// Loop each bind and create a new goroutine with a dns server and begin listening
	for _, bind := range Config.Binds {

		// We have 1 more to wait for
		wg.Add(1);

		// Spawn as a goroutine
		go startListening(mux, bind.Address, bind.Port)

	}

	// Wait for them all to exit
	wg.Wait()

}
