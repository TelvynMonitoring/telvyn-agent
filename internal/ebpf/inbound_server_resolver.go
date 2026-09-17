package ebpf

import (
	"github.com/ispwatch/collector/internal/ebpf/proc"
	"inet.af/netaddr"
)

// procInboundServerResolver obtains the local side of an accepted TCP socket.
// The lookup is only used on the first inbound PostgreSQL L7 event for a
// connection and the bridge caches the result by pid+fd.
type procInboundServerResolver struct{}

func (procInboundServerResolver) ResolveInboundServer(pid uint32, fd uint64) (netaddr.IPPort, bool) {
	fds, err := proc.ReadFds(pid)
	if err != nil {
		return netaddr.IPPort{}, false
	}
	inode := ""
	for _, candidate := range fds {
		if candidate.Fd == fd {
			inode = candidate.SocketInode
			break
		}
	}
	if inode == "" {
		return netaddr.IPPort{}, false
	}

	sockets, err := proc.GetSockets(pid)
	if err != nil {
		return netaddr.IPPort{}, false
	}
	for _, socket := range sockets {
		if socket.Inode == inode && !socket.SAddr.IsZero() && socket.SAddr.Port() != 0 {
			return socket.SAddr, true
		}
	}
	return netaddr.IPPort{}, false
}
