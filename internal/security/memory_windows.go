//go:build windows

package security

import (
	"go.uber.org/zap"
)

// MemoryProtection is a no-op stub on Windows (development only).
type MemoryProtection struct {
	logger *zap.Logger
}

// NewMemoryProtection creates a new memory protection service.
func NewMemoryProtection(logger *zap.Logger) *MemoryProtection {
	return &MemoryProtection{logger: logger}
}

// Apply logs a warning that memory protection is unavailable on Windows.
func (m *MemoryProtection) Apply() {
	m.logger.Warn("memory protection not available on Windows (development mode)")
}

// DisableCoreDumps is a no-op on Windows.
func (m *MemoryProtection) DisableCoreDumps() {}

// CheckPtraceProtection is a no-op on Windows.
func (m *MemoryProtection) CheckPtraceProtection() bool { return false }

// CheckMlock is a no-op on Windows.
func (m *MemoryProtection) CheckMlock() bool { return false }

// WipeBuffer overwrites a buffer with zeros.
func (m *MemoryProtection) WipeBuffer(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}
