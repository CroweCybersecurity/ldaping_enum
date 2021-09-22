package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
	"bytes"

	"gopkg.in/asn1-ber.v1"
)

// Flags
var flagDomain = flag.String("d", "", "`FQDN` to search against")
var flagDomainController = flag.String("s", "", "IP or `hostname` of domain controller to query")
var flagDomainControllerFile = flag.String("f", "", "`File` containing domain controllers, one per line")
var flagThreads = flag.Int("t", 10, "Number of guessing `threads`")
var flagOutputFile = flag.String("o", "found_users.txt", "Output `file` to write found users")
var flagGuessBuffer = flag.Int64("b", 1000, "Buffer of username guesses held in memory")

func main() {
	flag.Usage = func() {
		fmt.Printf("Usage: %s -d FQDN -s DC USERNAME_FILE\n", os.Args[0])
	    flag.PrintDefaults()
	}
	
	flag.Parse()
	// Domain must be provided
	if *flagDomain == "" {
		flag.Usage()
		log.Fatal("Domain (-d) is a required flag\n")
	}


	// Domain controller or list of domain controllers must be provided
	if *flagDomainController != "" && *flagDomainControllerFile != "" {
		flag.Usage()
		log.Fatal("You must provide either one domain controller (-s) or a file (-f), not both\n")
	}


	// We must have an input file
	if flag.NArg() != 1 {
		log.Fatal("You must supply a username file as the last arguement\n")
	}


	// Read domain controllers
	var domainControllers []string
	if *flagDomainControllerFile != "" {
		
		// Read list of domain controllers from file
		dcFile, err := os.Open(*flagDomainControllerFile)
		if err != nil {
			flag.Usage()
			log.Fatalf("Failed to open domain controller file (-f): %s\n", err)
		}
		
		scanner := bufio.NewScanner(dcFile)
		for scanner.Scan() {
			if strings.TrimSpace(scanner.Text()) != "" {
				domainControllers = append(domainControllers, scanner.Text())
			}
		}
		
	} else if *flagDomainController != "" {
		// 
		domainControllers = append(domainControllers, *flagDomainController)
		
	} else {
		
		// Search for domain controlers via SRV DNS records
		_, srvRecord, err := net.LookupSRV("ldap", "tcp", "dc._msdcs."+*flagDomain)
		if err != nil {
			log.Fatalf("Error pulling SRV records for AD and no domain controllers provided: %s", err)
		}
		for i := range srvRecord {
			domainControllers = append(domainControllers, srvRecord[i].Target)
		}
	}


	// Read list of usernames
	usernameFile, err := os.Open(flag.Arg(0))
	if err != nil {
		log.Fatalf("Failed to open username list file (argument 1): %s\n", err)
	}
	defer usernameFile.Close()
	guessScanner := bufio.NewScanner(usernameFile)


	// Check if output file exist
	if _, err := os.Stat(*flagOutputFile); !os.IsNotExist(err) {
		fmt.Printf("Output file (%s) exists already. Overwite? [Y/n] ", *flagOutputFile)
		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		input = strings.ToLower(input)
		
		if input  == "y\n" || input  == "\n" {
			fmt.Printf("Using file %s\n", *flagOutputFile)
		} else if input  == "n\n" {	
			os.Exit(1)
		} else {
			log.Fatalf("Unknown input: %s. Exiting", input)
		}
	}
	// Open output file
	outputFile, err := os.Create(*flagOutputFile)
	if err != nil {
		log.Fatalf("Unable to open the output file: %s", err)
	}
	defer outputFile.Close()
	
	
	// Create Channels
	guessChan := make(chan string, *flagGuessBuffer)
	foundChan := make(chan string, *flagGuessBuffer)
	
	// Create WaitGroup
	wg := new(sync.WaitGroup)
	writeWG := new(sync.WaitGroup)

	// Start the timer
	start := time.Now()

	wg.Add(1)
	go func() {
		for guessScanner.Scan() {
			guessChan <- guessScanner.Text()
		}

		close(guessChan)

		wg.Done()
	}()

	writeWG.Add(1)
	go writeFile(outputFile, foundChan, writeWG)

	// Create threads
	for i := 0; i < *flagThreads; i++ {
		wg.Add(1)
		go GuessThread(i+1, guessChan, foundChan, domainControllers, *flagDomain, wg)
	}

	wg.Wait()
	close(foundChan)
	writeWG.Wait()

	end := time.Now().Sub(start)
	log.Printf("Took: %s", end.String())
}

func GuessThread(id int, guesses, write chan string, dcs []string, domain string, wg *sync.WaitGroup) {
	defer wg.Done()
	// Setup connection map
	connMap := map[string]net.Conn{}

	// Setup UDP connections
	var added int
	for i := range dcs {
		conn, err := setupUDPConn(dcs[i])
		if err != nil {
			log.Printf("Could not establish connection: %s", err)
			continue
		}
		connMap[dcs[i]] = conn
		added++
	}
	if added == 0 {
		log.Printf("Unable to connect to any of the identified domain controllers. Exiting goroutine.")
		return
	}

	for {
		guess, more := <-guesses
		if more {
			// get the connection to guess against
			for _, conn := range connMap {
				// conduct a guess
				packet := buildPacket(guess, domain)
				conn.Write(packet.Bytes())

				// Read data
				resp := make([]byte, 1024)

				err := conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				if err != nil {
					log.Printf("Error setting read deadline: %s", err)
				}

				n, err := conn.Read(resp)
				if err != nil {
					if e, ok := err.(net.Error); !ok || !e.Timeout() {
						log.Printf("Error reading LDAP response: %s", e)
						// try another DC
						continue

					} else if e.Timeout() {
						log.Printf("[Thread:%d] Timeout in waiting for response.", id)
						continue

					}
				}

				found, err := decodePacket(resp, n)
				if err != nil {
					log.Printf("Error decoding packet: %s", err)
				}

				if found {
					log.Printf("FOUND USER: %s\n", guess)
					write <- guess
				}

				break
			}
		} else {
			// No more guesses coming
			return
		}
	}
}

func setupUDPConn(address string) (net.Conn, error) {
	// Create a UDP connection
	conn, err := net.Dial("udp", fmt.Sprintf("%s:%d", address, 389))
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func buildPacket(username, domain string) *ber.Packet {
	basePacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	basePacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "MessageID"))

	request := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 3, nil, "Search Request") // 3 == ApplicationSearchRequest
	request.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Base DN"))
	request.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, uint64(0), "Scope"))
	request.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, uint64(0), "Deref Aliases"))
	request.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, uint64(0), "Size Limit"))
	request.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, uint64(0), "Time Limit"))
	request.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "Types Only"))

	//  Build packet with LDAP filter
	filterPacket := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "And")       // 0 == FilterAnd
	packet1 := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, nil, "Equality Match") // 3 == FilterEqualityMatch
	packet1.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "DnsDomain", "Attribute"))
	packet1.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, domain, "Condition"))

	packet2 := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, nil, "Equality Match") // 3 == FilterEqualityMatch
	packet2.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "NtVer", "Attribute"))
	packet2.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "\x02\x00\x00\x00", "Condition"))

	packet3 := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, nil, "Equality Match") // 3 == FilterEqualityMatch
	packet3.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "User", "Attribute"))
	packet3.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, username, "Condition"))

	packet4 := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, nil, "Equality Match") // 3 == FilterEqualityMatch
	packet4.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "AAC", "Attribute"))
	packet4.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "\x10\x00\x00\x00", "Condition"))

	returnType := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Return Type")
	returnType.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "Netlogon", "Condition"))

	filterPacket.AppendChild(packet1)
	filterPacket.AppendChild(packet2)
	filterPacket.AppendChild(packet3)
	filterPacket.AppendChild(packet4)
	request.AppendChild(filterPacket)
	request.AppendChild(returnType)
	basePacket.AppendChild(request)

	return basePacket
}

func decodePacket(packet []byte, length int) (bool, error) {
	decodedPacket, err := ber.DecodePacketErr(packet[:length])
	if err != nil {
		return false, err
	}

	if bytes.Equal(decodedPacket.Data.Bytes(), []byte{0x02,0x01,0x00,0x65,0x07,0x0a,0x01,0x00,0x04,0x00,0x04,0x00}) {
		log.Fatal("Unexpected packet response: Are you using the correct FQDN? Ex. Contoso.com")
	} 

	resp := decodedPacket.Children[1].Children[1].Children[0].Children[1].Children[0].ByteValue[:1]

	switch resp[0] {
	case []byte("\x15")[0]:
		return false, nil
	case []byte("\x13")[0]:
		return true, nil
	}

	return false, nil
}

func writeFile(file *os.File, found chan string, done *sync.WaitGroup) {
	defer file.Close()
	defer done.Done()

	for {
		user, more := <-found
		if more {
			// write the file
			_, err := io.WriteString(file, user+"\r\n")
			if err != nil {
				log.Printf("Error writing user (%s) to file: %s", user, err)
			}
		} else {
			return
		}
	}
}
