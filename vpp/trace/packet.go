package trace

import "time"

// Packet is a traced packet.
type Packet struct {
	ID       int       // ID is a packet number
	Captures []Capture // Captures is the captured packet data
}

// Start returns the elapsed time since boot until the first capture.
func (p *Packet) Start() time.Duration {
	if first := p.FirstCapture(); first != nil {
		return first.Start
	}
	return 0
}

// FirstCapture returns the first capture of the packet
// or nil if packet has no captures.
func (p *Packet) FirstCapture() *Capture {
	if len(p.Captures) == 0 {
		return nil
	}
	return &p.Captures[0]
}

// LastCapture returns the last capture of the packet
// or nil if packet has no captures.
func (p *Packet) LastCapture() *Capture {
	if len(p.Captures) == 0 {
		return nil
	}
	return &p.Captures[len(p.Captures)-1]
}

// Capture is a part of traced packet.
type Capture struct {
	Name    string        // Name is a name of node in capture
	Start   time.Duration // Start is the elapsed time since boot
	Content string        // Content contains the captured data
}
