//go:build !noamdhsmp && linux

// Package collector implements AMD HSMP (Host System Management Port) metrics
// collection for AMD EPYC processors.
//
// Requirements:
//   - Linux kernel with amd_hsmp module loaded (modprobe amd_hsmp)
//   - Root privileges or CAP_SYS_RAWIO capability
//   - AMD EPYC Milan (Family 19h) or newer with HSMP enabled in BIOS
//
// The collector uses ioctl calls to /dev/hsmp to retrieve socket-level metrics
// including power consumption, DDR bandwidth, and clock frequencies.
package collector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"unsafe"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"
)

const amdHsmpCollectorSubsystem = "amd_hsmp"

// HSMP device path for ioctl interface.
const hsmpDevicePath = "/dev/hsmp"

// HSMP ioctl magic number and command.
const (
	hsmpIoctlMagic = 0xF8
	hsmpIoctlType  = 1
)

// HSMP message IDs (from linux/amd_hsmp.h).
// These are read-only GET commands.
const (
	HSMP_GET_SOCKET_POWER           = 0x04
	HSMP_GET_SOCKET_POWER_LIMIT     = 0x05
	HSMP_GET_SOCKET_POWER_LIMIT_MAX = 0x06
	HSMP_GET_FCLK_MCLK              = 0x0C
	HSMP_GET_CCLK_THROTTLE_LIMIT    = 0x0D
	HSMP_GET_C0_PERCENT             = 0x0E
	HSMP_GET_DDR_BANDWIDTH          = 0x14
)

// HSMP_MAX_MSG_LEN is the maximum number of arguments in a message.
const HSMP_MAX_MSG_LEN = 8

// hsmpMessage represents the HSMP ioctl message structure.
// This matches struct hsmp_message from linux/amd_hsmp.h.
type hsmpMessage struct {
	MsgID      uint32                   // Message ID
	NumArgs    uint16                   // Number of input argument words
	ResponseSz uint16                   // Number of expected output words
	Args       [HSMP_MAX_MSG_LEN]uint32 // Argument/response buffer
	SockInd    uint16                   // Socket number
	_          [2]byte                  // Padding
}

// Maximum number of sockets to probe during discovery.
// Current AMD EPYC platforms support up to 8 sockets (8P systems).
const hsmpMaxSockets = 16

// hsmpSocket stores pre-computed socket information.
type hsmpSocket struct {
	index int    // Socket index for ioctl calls
	label string // Pre-computed label for metrics
}

func init() {
	RegisterCollector(amdHsmpCollectorSubsystem, defaultDisabled, NewAmdHsmpCollector)
}

// amdHsmpCollector collects AMD HSMP metrics via ioctl.
type amdHsmpCollector struct {
	logger   *slog.Logger
	hostname string
	hsmpFd   int          // File descriptor for /dev/hsmp
	sockets  []hsmpSocket // Pre-computed socket info

	// Power metric descriptors
	powerInputDesc  *prometheus.Desc
	powerCapDesc    *prometheus.Desc
	powerCapMaxDesc *prometheus.Desc

	// Telemetry metric descriptors
	c0ResidencyDesc       *prometheus.Desc
	ddrMaxBwDesc          *prometheus.Desc
	ddrUtilizedBwDesc     *prometheus.Desc
	ddrUtilizedBwPctDesc  *prometheus.Desc
	mclkDesc              *prometheus.Desc
	fclkDesc              *prometheus.Desc
	cclkThrottleLimitDesc *prometheus.Desc
}

// NewAmdHsmpCollector returns a new Collector exposing AMD HSMP metrics.
func NewAmdHsmpCollector(logger *slog.Logger) (Collector, error) {
	// Try to open the HSMP device for ioctl
	fd, err := unix.Open(hsmpDevicePath, unix.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w (ensure amd_hsmp module is loaded and running as root)", hsmpDevicePath, err)
	}

	// Ensure FD is closed if we fail to create the collector
	// This prevents FD leaks on panics or errors during initialization
	defer func() {
		if fd >= 0 {
			unix.Close(fd)
		}
	}()

	logger.Info("AMD HSMP ioctl interface available", "device", hsmpDevicePath)

	labels := []string{"hostname", "socket"}

	collector := &amdHsmpCollector{
		logger:   logger,
		hostname: hostname,
		hsmpFd:   fd,
		// Power metrics
		powerInputDesc: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, amdHsmpCollectorSubsystem, "power_watts"),
			"Current socket power consumption in watts",
			labels, nil,
		),
		powerCapDesc: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, amdHsmpCollectorSubsystem, "power_cap_watts"),
			"Socket power cap in watts",
			labels, nil,
		),
		powerCapMaxDesc: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, amdHsmpCollectorSubsystem, "power_cap_max_watts"),
			"Maximum socket power cap in watts",
			labels, nil,
		),
		// Telemetry metrics
		c0ResidencyDesc: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, amdHsmpCollectorSubsystem, "c0_residency_percent"),
			"Percentage of cores in C0 state",
			labels, nil,
		),
		ddrMaxBwDesc: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, amdHsmpCollectorSubsystem, "ddr_max_bw_gbps"),
			"Theoretical maximum DDR bandwidth in GB/s",
			labels, nil,
		),
		ddrUtilizedBwDesc: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, amdHsmpCollectorSubsystem, "ddr_utilized_bw_gbps"),
			"Current utilized DDR bandwidth in GB/s",
			labels, nil,
		),
		ddrUtilizedBwPctDesc: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, amdHsmpCollectorSubsystem, "ddr_utilized_bw_percent"),
			"Percentage of current utilized DDR bandwidth",
			labels, nil,
		),
		mclkDesc: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, amdHsmpCollectorSubsystem, "mclk_mhz"),
			"Memory clock frequency in MHz",
			labels, nil,
		),
		fclkDesc: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, amdHsmpCollectorSubsystem, "fclk_mhz"),
			"Fabric clock frequency in MHz",
			labels, nil,
		),
		cclkThrottleLimitDesc: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, amdHsmpCollectorSubsystem, "cclk_throttle_limit_mhz"),
			"Core clock throttle limit in MHz",
			labels, nil,
		),
	}

	// Discover sockets by probing
	collector.discoverSockets()

	// Transfer FD ownership to collector (prevent defer from closing it)
	fd = -1

	return collector, nil
}

// discoverSockets probes for available HSMP sockets.
func (c *amdHsmpCollector) discoverSockets() {
	c.sockets = nil

	// Probe sockets 0 to hsmpMaxSockets-1
	for i := 0; i < hsmpMaxSockets; i++ {
		if _, err := c.getSocketPower(i); err == nil {
			c.sockets = append(c.sockets, hsmpSocket{
				index: i,
				label: strconv.Itoa(i),
			})
		}
	}

	c.logger.Info("Discovered HSMP sockets", "count", len(c.sockets))
}

// Update implements Collector and exposes AMD HSMP metrics.
func (c *amdHsmpCollector) Update(ch chan<- prometheus.Metric) error {
	if len(c.sockets) == 0 {
		return ErrNoData
	}

	for _, socket := range c.sockets {
		// Power
		if power, err := c.getSocketPower(socket.index); err == nil {
			ch <- prometheus.MustNewConstMetric(c.powerInputDesc, prometheus.GaugeValue, float64(power)/1000.0, c.hostname, socket.label)
		} else {
			c.logger.Debug("Failed to get socket power", "socket", socket.index, "err", err)
		}

		if powerLimit, err := c.getSocketPowerLimit(socket.index); err == nil {
			ch <- prometheus.MustNewConstMetric(c.powerCapDesc, prometheus.GaugeValue, float64(powerLimit)/1000.0, c.hostname, socket.label)
		} else {
			c.logger.Debug("Failed to get socket power limit", "socket", socket.index, "err", err)
		}

		if powerLimitMax, err := c.getSocketPowerLimitMax(socket.index); err == nil {
			ch <- prometheus.MustNewConstMetric(c.powerCapMaxDesc, prometheus.GaugeValue, float64(powerLimitMax)/1000.0, c.hostname, socket.label)
		} else {
			c.logger.Debug("Failed to get socket power limit max", "socket", socket.index, "err", err)
		}

		// C0 Residency
		if c0, err := c.getC0Percent(socket.index); err == nil {
			ch <- prometheus.MustNewConstMetric(c.c0ResidencyDesc, prometheus.GaugeValue, float64(c0), c.hostname, socket.label)
		} else {
			c.logger.Debug("Failed to get C0 residency", "socket", socket.index, "err", err)
		}

		// DDR Bandwidth
		if maxBw, utilizedBw, utilizedPct, err := c.getDDRBandwidth(socket.index); err == nil {
			ch <- prometheus.MustNewConstMetric(c.ddrMaxBwDesc, prometheus.GaugeValue, float64(maxBw), c.hostname, socket.label)
			ch <- prometheus.MustNewConstMetric(c.ddrUtilizedBwDesc, prometheus.GaugeValue, float64(utilizedBw), c.hostname, socket.label)
			ch <- prometheus.MustNewConstMetric(c.ddrUtilizedBwPctDesc, prometheus.GaugeValue, float64(utilizedPct), c.hostname, socket.label)
		} else {
			c.logger.Debug("Failed to get DDR bandwidth", "socket", socket.index, "err", err)
		}

		// FCLK and MCLK
		if fclk, mclk, err := c.getFclkMclk(socket.index); err == nil {
			ch <- prometheus.MustNewConstMetric(c.fclkDesc, prometheus.GaugeValue, float64(fclk), c.hostname, socket.label)
			ch <- prometheus.MustNewConstMetric(c.mclkDesc, prometheus.GaugeValue, float64(mclk), c.hostname, socket.label)
		} else {
			c.logger.Debug("Failed to get FCLK/MCLK", "socket", socket.index, "err", err)
		}

		// CCLK Throttle Limit
		if cclk, err := c.getCclkThrottleLimit(socket.index); err == nil {
			ch <- prometheus.MustNewConstMetric(c.cclkThrottleLimitDesc, prometheus.GaugeValue, float64(cclk), c.hostname, socket.label)
		} else {
			c.logger.Debug("Failed to get CCLK throttle limit", "socket", socket.index, "err", err)
		}
	}

	return nil
}

// Stop releases system resources used by the collector.
func (c *amdHsmpCollector) Stop(_ context.Context) error {
	c.logger.Debug("Stopping", "collector", amdHsmpCollectorSubsystem)

	if c.hsmpFd >= 0 {
		unix.Close(c.hsmpFd)
		c.hsmpFd = -1
	}

	return nil
}

// hsmpIoctl performs an HSMP ioctl call.
func (c *amdHsmpCollector) hsmpIoctl(msg *hsmpMessage) error {
	if c.hsmpFd < 0 {
		return errors.New("HSMP device not open")
	}

	// HSMP_IOCTL_CMD = _IOWR(HSMP_IOCTL_MAGIC, HSMP_IOCTL_TYPE, struct hsmp_message)
	// _IOWR = direction (3) << 30 | size << 16 | type << 8 | nr
	msgSize := uint32(unsafe.Sizeof(*msg))
	ioctlCmd := uint32(3)<<30 | msgSize<<16 | uint32(hsmpIoctlMagic)<<8 | hsmpIoctlType

	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(c.hsmpFd), uintptr(ioctlCmd), uintptr(unsafe.Pointer(msg)))
	if errno != 0 {
		return fmt.Errorf("HSMP ioctl failed: %v", errno)
	}

	return nil
}

// getSocketPower returns the current socket power in milliwatts.
func (c *amdHsmpCollector) getSocketPower(socketIdx int) (uint32, error) {
	msg := hsmpMessage{
		MsgID:      HSMP_GET_SOCKET_POWER,
		NumArgs:    0,
		ResponseSz: 1,
		SockInd:    uint16(socketIdx),
	}

	if err := c.hsmpIoctl(&msg); err != nil {
		return 0, err
	}

	return msg.Args[0], nil
}

// getSocketPowerLimit returns the socket power limit in milliwatts.
func (c *amdHsmpCollector) getSocketPowerLimit(socketIdx int) (uint32, error) {
	msg := hsmpMessage{
		MsgID:      HSMP_GET_SOCKET_POWER_LIMIT,
		NumArgs:    0,
		ResponseSz: 1,
		SockInd:    uint16(socketIdx),
	}

	if err := c.hsmpIoctl(&msg); err != nil {
		return 0, err
	}

	return msg.Args[0], nil
}

// getSocketPowerLimitMax returns the maximum socket power limit in milliwatts.
func (c *amdHsmpCollector) getSocketPowerLimitMax(socketIdx int) (uint32, error) {
	msg := hsmpMessage{
		MsgID:      HSMP_GET_SOCKET_POWER_LIMIT_MAX,
		NumArgs:    0,
		ResponseSz: 1,
		SockInd:    uint16(socketIdx),
	}

	if err := c.hsmpIoctl(&msg); err != nil {
		return 0, err
	}

	return msg.Args[0], nil
}

// getC0Percent returns the C0 residency percentage.
func (c *amdHsmpCollector) getC0Percent(socketIdx int) (uint32, error) {
	msg := hsmpMessage{
		MsgID:      HSMP_GET_C0_PERCENT,
		NumArgs:    0,
		ResponseSz: 1,
		SockInd:    uint16(socketIdx),
	}

	if err := c.hsmpIoctl(&msg); err != nil {
		return 0, err
	}

	return msg.Args[0], nil
}

// getDDRBandwidth returns DDR bandwidth info: max (GB/s), utilized (GB/s), utilized percent.
func (c *amdHsmpCollector) getDDRBandwidth(socketIdx int) (uint32, uint32, uint32, error) {
	msg := hsmpMessage{
		MsgID:      HSMP_GET_DDR_BANDWIDTH,
		NumArgs:    0,
		ResponseSz: 1,
		SockInd:    uint16(socketIdx),
	}

	if err := c.hsmpIoctl(&msg); err != nil {
		return 0, 0, 0, err
	}

	// Response is packed: bits[31:20] = max BW, bits[19:8] = utilized BW, bits[7:0] = utilized percent
	response := msg.Args[0]
	maxBw := (response >> 20) & 0xFFF
	utilizedBw := (response >> 8) & 0xFFF
	utilizedPct := response & 0xFF

	return maxBw, utilizedBw, utilizedPct, nil
}

// getFclkMclk returns the fabric clock and memory clock in MHz.
func (c *amdHsmpCollector) getFclkMclk(socketIdx int) (uint32, uint32, error) {
	msg := hsmpMessage{
		MsgID:      HSMP_GET_FCLK_MCLK,
		NumArgs:    0,
		ResponseSz: 2,
		SockInd:    uint16(socketIdx),
	}

	if err := c.hsmpIoctl(&msg); err != nil {
		return 0, 0, err
	}

	fclk := msg.Args[0]
	mclk := msg.Args[1]

	return fclk, mclk, nil
}

// getCclkThrottleLimit returns the CCLK throttle limit in MHz.
func (c *amdHsmpCollector) getCclkThrottleLimit(socketIdx int) (uint32, error) {
	msg := hsmpMessage{
		MsgID:      HSMP_GET_CCLK_THROTTLE_LIMIT,
		NumArgs:    0,
		ResponseSz: 1,
		SockInd:    uint16(socketIdx),
	}

	if err := c.hsmpIoctl(&msg); err != nil {
		return 0, err
	}

	return msg.Args[0], nil
}
