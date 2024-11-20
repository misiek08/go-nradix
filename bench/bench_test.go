package bench

import (
	"fmt"
	"testing"
	"bytes"
	"net"
	"strings"
	"errors"

	misiek "github.com/misiek08/go-nradix"
	"github.com/asergeyev/nradix"
)


var fullMask net.IPMask

func init() {
	fullMask = net.CIDRMask(128, 128)
}

var (
	ErrNodeBusy = errors.New("Node Busy")
	ErrNotFound = errors.New("No Such Node")
	ErrBadIP    = errors.New("Bad IP address or mask")
)

func DisabledBenchmarkSimpleFindMisiek(b *testing.B) {
	t := misiek.NewTree(0)
	for i := 0; i < 100; i++ {
		for j := 0; j < 100; j++ {
			for k := 0; k < 100; k++ {
				t.AddCIDR(fmt.Sprintf("%d.%d.%d.0/24", i, j, k), 1337)
			}
		}	
	}
	for i := 0; i < b.N; i++ {
		_, err := t.FindCIDR("73.26.28.24")
		if err != nil {
			b.Error("error occured in FindCIDR")
		}
	}
}

func DisabledBenchmarkSimpleFindOriginal(b *testing.B) {
	t := nradix.NewTree(0)
	for i := 0; i < 100; i++ {
		for j := 0; j < 100; j++ {
			for k := 0; k < 100; k++ {
				t.AddCIDR(fmt.Sprintf("%d.%d.%d.0/24", i, j, k), 1337)
			}
		}	
	}
	for i := 0; i < b.N; i++ {
		_, err := t.FindCIDR("73.26.28.24")
		if err != nil {
			b.Error("error occured in FindCIDR")
		}
	}
}

func BenchmarkParseCIDR(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, err := parsecidr("73.26.28.24")
		if err != nil {
			b.Error("error occured in parsing")
		}
	}
}

func BenchmarkParseCIDR4(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, err := parsecidr4([]byte("73.26.28.24"))
		if err != nil {
			b.Error("error occured in parsing")
		}
	}
}
func BenchmarkParseCIDR6(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, err := parsecidr6([]byte("73.26.28.24"))
		if err != nil {
			b.Error("error occured in parsing")
		}
	}
}
func BenchmarkParsePart(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = bytes.IndexByte([]byte("73.26.28.24"), '/')
		// _ = net.ParseIP("73.26.28.24")
	}
}

func parsecidr(cidr string) (net.IP, net.IPMask, error) {
	p := strings.IndexByte(cidr, '/')
	if p == -1 {
		ip := net.ParseIP(cidr)
		return ip.To16(), fullMask, nil
	}

	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, nil, err
	}
	
	prefixLength, _ := ipNet.Mask.Size()
	if len(ip) == net.IPv4len {
		prefixLength += 96
	}
	mask := net.CIDRMask(prefixLength, 128)

	return ip.To16(), mask, nil
}

func parsecidr4(cidr []byte) (uint32, uint32, error) {
	var mask uint32
	p := bytes.IndexByte(cidr, '/')
	if p > 0 {
		for _, c := range cidr[p+1:] {
			if c < '0' || c > '9' {
				return 0, 0, ErrBadIP
			}
			mask = mask*10 + uint32(c-'0')
		}
		mask = 0xffffffff << (32 - mask)
		cidr = cidr[:p]
	} else {
		mask = 0xffffffff
	}
	ip, err := loadip4(cidr)
	if err != nil {
		return 0, 0, err
	}
	return ip, mask, nil
}

func parsecidr6(cidr []byte) (net.IP, net.IPMask, error) {
	p := bytes.IndexByte(cidr, '/')
	if p > 0 {
		_, ipm, err := net.ParseCIDR(string(cidr))
		if err != nil {
			return nil, nil, err
		}
		return ipm.IP, ipm.Mask, nil
	}
	ip := net.ParseIP(string(cidr))
	if ip == nil {
		return nil, nil, ErrBadIP
	}
	return ip, net.IPMask{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, nil
}

func loadip4(ipstr []byte) (uint32, error) {
	var (
		ip  uint32
		oct uint32
		b   byte
		num byte
	)

	for _, b = range ipstr {
		switch {
		case b == '.':
			num++
			if 0xffffffff-ip < oct {
				return 0, ErrBadIP
			}
			ip = ip<<8 + oct
			oct = 0
		case b >= '0' && b <= '9':
			oct = oct*10 + uint32(b-'0')
			if oct > 255 {
				return 0, ErrBadIP
			}
		default:
			return 0, ErrBadIP
		}
	}
	if num != 3 {
		return 0, ErrBadIP
	}
	if 0xffffffff-ip < oct {
		return 0, ErrBadIP
	}
	return ip<<8 + oct, nil
}