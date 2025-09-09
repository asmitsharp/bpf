package main

import (
	"bytes"
	_ "embed"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:embed ebpf/packet_filter.o
var ebpfProgram []byte

func main() {
	var (
		ifaceName = flag.String("interface", "eth0", "Network interface to attach the eBPF program to")
		port      = flag.Int("port", 4040, "Port to filter packets on")
	)
	flag.Parse()

	fmt.Printf("Starting packet dropper on interface %s, port %d\n", *ifaceName, *port)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(ebpfProgram))
	if err != nil {
		log.Fatal("Failed to load eBPF program:", err)
	}

	//eBPF collection (programs + maps)
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatal("Failed to create eBPF collection:", err)
	}
	defer coll.Close()

	portMap := coll.Maps["port_map"]
	key := uint32(0)
	value := uint16(*port)
	if err := portMap.Update(key, value, ebpf.UpdateAny); err != nil {
		log.Fatal("Failed to update port map:", err)
	}

	iface, err := net.InterfaceByName(*ifaceName)
	if err != nil {
		log.Fatal("Failed to get interface:", err)
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   coll.Programs["drop_tcp_packets"],
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("Failed to attach XDP program:", err)
	}
	defer xdpLink.Close()

	fmt.Printf("eBPF program attached! Dropping TCP packets on port %d\n", *port)
	fmt.Println("Press Ctrl+C to stop...")

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	fmt.Println("\nstopping packet dropper...")

}
