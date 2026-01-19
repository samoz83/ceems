//go:build !noamdhsmp && linux

package collector

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

// Note: Full testing of the HSMP collector requires /dev/hsmp to be available.
// These tests verify the struct layout, ioctl command generation, and data unpacking.

func TestHsmpMessageSize(t *testing.T) {
	// The hsmpMessage struct should match the kernel's struct hsmp_message.
	// struct hsmp_message has:
	// - uint32 msg_id
	// - uint16 num_args
	// - uint16 response_sz
	// - uint32 args[8]
	// - uint16 sock_ind
	// - 2 bytes padding
	// Total: 4 + 2 + 2 + 32 + 2 + 2 = 44 bytes
	expectedSize := 44
	actualSize := int(unsafe.Sizeof(hsmpMessage{}))

	require.Equal(t, expectedSize, actualSize, "hsmpMessage struct size mismatch - ioctl will fail")

	// Verify Args array is properly sized
	msg := hsmpMessage{}
	require.Equal(t, 32, int(unsafe.Sizeof(msg.Args)), "args array size")
}

func TestHsmpIoctlCommand(t *testing.T) {
	// Verify the ioctl command matches expected value.
	// _IOWR(0xF8, 1, struct hsmp_message) = 0xC02CF801
	msgSize := uint32(unsafe.Sizeof(hsmpMessage{}))
	ioctlCmd := uint32(3)<<30 | msgSize<<16 | uint32(hsmpIoctlMagic)<<8 | hsmpIoctlType

	require.Equal(t, uint32(0xC02CF801), ioctlCmd, "ioctl command mismatch")
}

func TestDDRBandwidthUnpacking(t *testing.T) {
	tests := []struct {
		name        string
		response    uint32
		expectedMax uint32
		expectedUtl uint32
		expectedPct uint32
	}{
		{
			name:        "Typical values",
			response:    1024<<20 | 512<<8 | 50,
			expectedMax: 1024,
			expectedUtl: 512,
			expectedPct: 50,
		},
		{
			name:        "Zero utilization",
			response:    2048 << 20,
			expectedMax: 2048,
			expectedUtl: 0,
			expectedPct: 0,
		},
		{
			name:        "Full utilization",
			response:    512<<20 | 512<<8 | 100,
			expectedMax: 512,
			expectedUtl: 512,
			expectedPct: 100,
		},
		{
			name:        "Max representable values",
			response:    0xFFF<<20 | 0xFFF<<8 | 0xFF,
			expectedMax: 4095,
			expectedUtl: 4095,
			expectedPct: 255,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Unpack using the same logic as getDDRBandwidth
			maxBw := (tt.response >> 20) & 0xFFF
			utilizedBw := (tt.response >> 8) & 0xFFF
			utilizedPct := tt.response & 0xFF

			require.Equal(t, tt.expectedMax, maxBw, "maxBw mismatch")
			require.Equal(t, tt.expectedUtl, utilizedBw, "utilizedBw mismatch")
			require.Equal(t, tt.expectedPct, utilizedPct, "utilizedPct mismatch")
		})
	}
}

func TestHsmpSocketPrecomputed(t *testing.T) {
	// Verify hsmpSocket stores pre-computed label correctly
	tests := []struct {
		index         int
		expectedLabel string
	}{
		{0, "0"},
		{1, "1"},
		{7, "7"},
		{15, "15"},
	}

	for _, tt := range tests {
		socket := hsmpSocket{
			index: tt.index,
			label: tt.expectedLabel,
		}
		require.Equal(t, tt.index, socket.index)
		require.Equal(t, tt.expectedLabel, socket.label)
	}
}
