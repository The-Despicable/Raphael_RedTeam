// opsec.go — scan-hygiene knobs for the raw SYN path.
//
// These exist to make the probe stream harder to attribute and harder to
// fingerprint on the target side:
//
//	TTL randomization      defeats simple TTL-based OS/topology inference
//	source-port strategy   random vs fixed tuple pressure
//	jitter                 breaks constant-rate fingerprints and periodicity
//	TCP timestamps         varies the option set per probe
//	IP fragmentation       splits the SYN across tiny fragments
//	decoy sources          interleaves spoofed-source SYNs with real probes
//
// Nothing here touches the scope gate: decoys are validated against the same
// allow list by the caller before a packet is built.
package main

import (
	"encoding/binary"
	"math/rand"
	"net"
	"time"
)

type opsecConfig struct {
	ttlLo, ttlHi uint8
	window       bool // random window instead of the fixed 64240
	timestamps   bool // add TS option (32-byte TCP header)
	fragSize     int  // >0: fragment payload at this many bytes (multiple of 8)
	fixedSport   bool // reuse one source port instead of random per probe
	jitter       time.Duration
	decoys       []ipRange
	decoyN       int
	fixedPort    uint16
}

func (o *opsecConfig) pickTTL() uint8 {
	if o == nil || o.ttlHi == 0 {
		return 64
	}
	if o.ttlLo >= o.ttlHi {
		return o.ttlLo
	}
	return uint8(o.ttlLo + uint8(rand.Intn(int(o.ttlHi-o.ttlLo+1))))
}

func (o *opsecConfig) pickWindow() uint16 {
	if o != nil && o.window {
		return uint16(1024 + rand.Intn(63*1024))
	}
	return 64240
}

func (o *opsecConfig) pickSport() uint16 {
	if o != nil && o.fixedSport {
		if o.fixedPort == 0 {
			o.fixedPort = uint16(32768 + rand.Intn(28000))
		}
		return o.fixedPort
	}
	return uint16(32768 + rand.Intn(28000))
}

// pickDecoy returns a spoofed source different from dst, if a pool is set.
func (o *opsecConfig) pickDecoy(dst uint32) (uint32, bool) {
	if o == nil || len(o.decoys) == 0 || o.decoyN <= 0 {
		return 0, false
	}
	var total uint64
	for _, r := range o.decoys {
		total += uint64(r.hi) - uint64(r.lo) + 1
	}
	if total == 0 {
		return 0, false
	}
	for attempt := 0; attempt < 4; attempt++ {
		pick := uint64(rand.Int63n(int64(total)))
		for _, r := range o.decoys {
			size := uint64(r.hi) - uint64(r.lo) + 1
			if pick < size {
				ip := r.lo + uint32(pick)
				if ip != dst {
					return ip, true
				}
				break
			}
			pick -= size
		}
	}
	return 0, false
}

func (o *opsecConfig) jitterSleep() {
	if o == nil || o.jitter <= 0 {
		return
	}
	time.Sleep(time.Duration(rand.Int63n(int64(o.jitter))))
}

// buildSYNSeg builds a complete IPv4+TCP SYN with the given fingerprint.
func buildSYNSeg(src, dst net.IP, sport, dport uint16, seq uint32, ttl uint8, win uint16, ts bool) []byte {
	tcpLen := 20
	if ts {
		tcpLen = 32
	}
	pkt := make([]byte, 20+tcpLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	binary.BigEndian.PutUint16(pkt[4:6], uint16(rand.Uint32()))
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000) // DF
	pkt[8] = ttl
	pkt[9] = 6
	copy(pkt[12:16], src.To4())
	copy(pkt[16:20], dst.To4())
	binary.BigEndian.PutUint16(pkt[10:12], checksum(pkt[0:20]))

	tcp := pkt[20:]
	binary.BigEndian.PutUint16(tcp[0:2], sport)
	binary.BigEndian.PutUint16(tcp[2:4], dport)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	tcp[12] = byte(tcpLen/4) << 4
	tcp[13] = 0x02 // SYN
	binary.BigEndian.PutUint16(tcp[14:16], win)
	if ts {
		opt := tcp[20:32]
		opt[0], opt[1] = 1, 1 // NOP NOP
		opt[2], opt[3] = 8, 8 // kind=8 len=8 (timestamp)
		binary.BigEndian.PutUint32(opt[4:8], uint32(time.Now().UnixNano()))
		binary.BigEndian.PutUint32(opt[8:12], 0)
	}

	ph := make([]byte, 0, 12+tcpLen)
	ph = append(ph, src.To4()...)
	ph = append(ph, dst.To4()...)
	ph = append(ph, 0, 6)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(tcp)))
	ph = append(ph, l[:]...)
	binary.BigEndian.PutUint16(tcp[16:18], checksum(append(ph, tcp...)))
	return pkt
}

// fragmentPacket splits the payload into fragments of size bytes (multiple of
// 8). A size of 0, or a payload that fits, returns the packet untouched.
func fragmentPacket(pkt []byte, size int) [][]byte {
	if size <= 0 || size%8 != 0 || len(pkt) <= 20+size {
		return [][]byte{pkt}
	}
	payload := pkt[20:]
	ipid := binary.BigEndian.Uint16(pkt[4:6])
	out := make([][]byte, 0, (len(payload)+size-1)/size)
	for off := 0; off < len(payload); off += size {
		end := off + size
		if end > len(payload) {
			end = len(payload)
		}
		frag := make([]byte, 20+end-off)
		copy(frag[:20], pkt[:20])
		binary.BigEndian.PutUint16(frag[2:4], uint16(len(frag)))
		binary.BigEndian.PutUint16(frag[4:6], ipid)
		flags := uint16(0)
		if end < len(payload) {
			flags = 0x2000 // MF
		}
		binary.BigEndian.PutUint16(frag[6:8], flags|uint16(off/8)&0x1fff)
		binary.BigEndian.PutUint16(frag[10:12], 0)
		binary.BigEndian.PutUint16(frag[10:12], checksum(frag[:20]))
		copy(frag[20:], payload[off:end])
		out = append(out, frag)
	}
	return out
}
