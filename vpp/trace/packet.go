package trace

import "time"

// Packet is a traced packet.
type Packet struct {
	ID       int       // ID is a packet number
	Captures []Capture // Captures is the captured packet data
}

// Capture is a part of traced packet.
type Capture struct {
	Name    string        // Name is a name of node in capture
	Start   time.Duration // Start is the elapsed time since boot
	Content string        // Content contains the captured data
}
