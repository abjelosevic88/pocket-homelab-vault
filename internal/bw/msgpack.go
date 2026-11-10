package bw

import (
	"encoding/binary"
	"math"
	"time"
)

// The live-sync hub speaks SignalR with the MessagePack protocol: each frame
// is a varint length followed by one MessagePack array. This is the small
// encoder for the values those frames hold.

// Nil is MessagePack nil.
type Nil struct{}

// Timestamp is a MessagePack timestamp (extension -1).
type Timestamp time.Time

// KV is one key/value of an ordered MessagePack map.
type KV struct {
	K string
	V any
}

// Map is an ordered MessagePack map.
type Map []KV

func appendValue(b []byte, v any) []byte {
	switch x := v.(type) {
	case nil, Nil:
		return append(b, 0xc0)
	case bool:
		if x {
			return append(b, 0xc3)
		}
		return append(b, 0xc2)
	case int:
		return appendInt(b, int64(x))
	case int64:
		return appendInt(b, x)
	case string:
		return appendString(b, x)
	case *string:
		if x == nil {
			return append(b, 0xc0)
		}
		return appendString(b, *x)
	case []any:
		n := len(x)
		switch {
		case n < 16:
			b = append(b, 0x90|byte(n))
		case n <= math.MaxUint16:
			b = append(b, 0xdc, byte(n>>8), byte(n))
		default:
			b = append(b, 0xdd)
			b = binary.BigEndian.AppendUint32(b, uint32(n))
		}
		for _, e := range x {
			b = appendValue(b, e)
		}
		return b
	case Map:
		n := len(x)
		switch {
		case n < 16:
			b = append(b, 0x80|byte(n))
		default:
			b = append(b, 0xde, byte(n>>8), byte(n))
		}
		for _, kv := range x {
			b = appendString(b, kv.K)
			b = appendValue(b, kv.V)
		}
		return b
	case Timestamp:
		t := time.Time(x).UTC()
		secs, nanos := uint64(t.Unix()), uint64(t.Nanosecond())
		// timestamp 64: 30-bit nanoseconds, 34-bit seconds
		b = append(b, 0xd7, 0xff)
		return binary.BigEndian.AppendUint64(b, nanos<<34|secs)
	}
	return append(b, 0xc0)
}

func appendInt(b []byte, n int64) []byte {
	switch {
	case n >= 0 && n < 128:
		return append(b, byte(n))
	case n < 0 && n >= -32:
		return append(b, byte(n))
	case n >= 0 && n <= math.MaxUint8:
		return append(b, 0xcc, byte(n))
	case n >= 0 && n <= math.MaxUint16:
		return append(b, 0xcd, byte(n>>8), byte(n))
	case n >= 0 && n <= math.MaxUint32:
		b = append(b, 0xce)
		return binary.BigEndian.AppendUint32(b, uint32(n))
	}
	b = append(b, 0xd3)
	return binary.BigEndian.AppendUint64(b, uint64(n))
}

func appendString(b []byte, s string) []byte {
	n := len(s)
	switch {
	case n < 32:
		b = append(b, 0xa0|byte(n))
	case n <= math.MaxUint8:
		b = append(b, 0xd9, byte(n))
	case n <= math.MaxUint16:
		b = append(b, 0xda, byte(n>>8), byte(n))
	default:
		b = append(b, 0xdb)
		b = binary.BigEndian.AppendUint32(b, uint32(n))
	}
	return append(b, s...)
}

// Frame is one SignalR binary frame: the varint length, then the value.
func Frame(v any) []byte {
	body := appendValue(nil, v)
	var head []byte
	n := len(body)
	for {
		part := byte(n & 0x7f)
		n >>= 7
		if n > 0 {
			part |= 0x80
		}
		head = append(head, part)
		if n == 0 {
			break
		}
	}
	return append(head, body...)
}

// Update types the apps understand (Bitwarden's PushType).
const (
	SyncCipherUpdate = 0
	SyncCipherCreate = 1
	SyncLoginDelete  = 2
	SyncFolderDelete = 3
	SyncCiphers      = 4
	SyncVault        = 5
	SyncFolderCreate = 7
	SyncFolderUpdate = 8
	SyncSettings     = 10
	LogOut           = 11
)

// UpdateFrame is a "ReceiveMessage" invocation telling apps what changed.
// contextID is the device that made the change (it skips its own update).
func UpdateFrame(kind int, contextID string, payload Map) []byte {
	var ctx any = Nil{}
	if contextID != "" {
		ctx = contextID
	}
	return Frame([]any{1, Map{}, Nil{}, "ReceiveMessage", []any{Map{{"ContextId", ctx}, {"Type", kind}, {"Payload", payload}}}})
}

// PingFrame is a SignalR ping.
func PingFrame() []byte { return Frame([]any{6}) }
