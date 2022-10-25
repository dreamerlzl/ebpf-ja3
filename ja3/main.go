//go:build linux
// +build linux

package main

import (
	"C"
	"errors"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/open-ch/ja3"
)
import (
	"encoding/hex"
	"encoding/json"
	"io"

	"github.com/cilium/ebpf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc "$BPF_CLANG" -cflags "$BPF_CFLAGS" -target native -type event bpf xdp.c -- -I../headers
func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Please specify a network interface")
	}

	// Look up the network interface by name.
	ifaceName := os.Args[1]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	if err = rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err = loadBpfObjects(&objs, nil); err != nil {
		// print eBPF verifier log, if any
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			for _, line := range ve.Log {
				log.Println(line)
			}
		}
		log.Fatalf("loading objects: %s", err.Error())
	}
	defer objs.Close()

	// Attach the program. may need kernel 5.7+
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpFunc,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()

	// here we use perf event; ringbuffer is not available until kernel 5.8
	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}
	defer rd.Close()

	go func() {
		// Wait for a signal and close the perf reader,
		// which will interrupt rd.Read() and make the program exit.
		<-stopper
		log.Println("Received signal, exiting program..")

		if err := rd.Close(); err != nil {
			log.Fatalf("closing perf event reader: %s", err)
		}
	}()

	var ethernet layers.Ethernet
	var ipv4 layers.IPv4
	var ipv6 layers.IPv6
	var tcp layers.TCP
	var decoded []gopacket.LayerType
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ethernet, &ipv4, &ipv6, &tcp)
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Printf("reading from perf event reader: %s", err)
			continue
		}

		if record.LostSamples != 0 {
			log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
			continue
		}

		// the first 4 byte are pkt_len and a dummy; see xdp.c
		packet := record.RawSample[4:]
		_ = parser.DecodeLayers(packet, &decoded) // this err is sure to be not nil since the payload could not be parsed
		isTCP := false
		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeTCP:
				isTCP = true
				j, err := ja3.ComputeJA3FromSegment(tcp.Payload)
				// Check if the parsing was successful, else segment is no Client Hello
				if err != nil {
					log.Printf("error from parsing tcp payload: %v\n", err)
					continue
				}

				// Prepare capture info for JSON marshalling
				var srcIP, dstIP string
				for _, layerType := range decoded {
					switch layerType {
					case layers.LayerTypeIPv4:
						srcIP = ipv4.SrcIP.String()
						dstIP = ipv4.DstIP.String()
					case layers.LayerTypeIPv6:
						srcIP = ipv6.SrcIP.String()
						dstIP = ipv6.DstIP.String()
					}
				}

				err = writeJSON(dstIP, int(tcp.DstPort), srcIP, int(tcp.SrcPort), j, os.Stdout)
				if err != nil {
					log.Fatal(err)
				}
			}
		}
		if !isTCP {
			log.Printf("receive a non-TCP packet in user space; length: %v bytes", len(packet))
			content := hex.EncodeToString(packet)
			log.Println(content)
		}
	}
}

func writeJSON(dstIP string, dstPort int, srcIP string, srcPort int, j *ja3.JA3, writer io.Writer) error {
	// Use the same convention as in the official Python implementation
	js, err := json.Marshal(struct {
		DstIP     string `json:"destination_ip"`
		DstPort   int    `json:"destination_port"`
		JA3String string `json:"ja3"`
		JA3Hash   string `json:"ja3_digest"`
		SrcIP     string `json:"source_ip"`
		SrcPort   int    `json:"source_port"`
		SNI       string `json:"sni"`
	}{
		dstIP,
		dstPort,
		string(j.GetJA3String()),
		j.GetJA3Hash(),
		srcIP,
		srcPort,
		j.GetSNI(),
	})
	if err != nil {
		return err
	}

	// Write the JSON to the writer
	writer.Write(js)
	writer.Write([]byte("\n"))
	return nil
}
