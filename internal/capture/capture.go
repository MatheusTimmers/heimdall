package capture

import (
	"net"
	"syscall"
	"unsafe"
)

func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

func setPromisc(iface string, fd int) error {
	var ifr [syscall.IFNAMSIZ + 16]byte
	copy(ifr[:], iface)

	// 1) Pega as flags atuais
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		uintptr(syscall.SIOCGIFFLAGS),
		uintptr(unsafe.Pointer(&ifr[0])),
	)
	if errno != 0 {
		return errno
	}

	flags := *(*uint16)(unsafe.Pointer(&ifr[syscall.IFNAMSIZ]))
	flags |= syscall.IFF_PROMISC
	*(*uint16)(unsafe.Pointer(&ifr[syscall.IFNAMSIZ])) = flags

	_, _, errno = syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		uintptr(syscall.SIOCSIFFLAGS),
		uintptr(unsafe.Pointer(&ifr[0])),
	)
	if errno != 0 {
		return errno
	}
	return nil
}

func StartRawSocket(iface string) (<-chan []byte, func(), error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return nil, nil, err
	}

	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		syscall.Close(fd)
		return nil, nil, err
	}

	addr := &syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ALL),
		Ifindex:  ifi.Index,
	}

	if err := syscall.Bind(fd, addr); err != nil {
		syscall.Close(fd)
		return nil, nil, err
	}

	if err := setPromisc(iface, fd); err != nil {
		syscall.Close(fd)
		return nil, nil, err
	}

	stop := make(chan struct{})
	out := make(chan []byte, 100)
	go func() {
		defer close(out)
		defer syscall.Close(fd)
		buf := make([]byte, 1<<16)
		for {
			select {
			case <-stop:
				return
			default:
				n, _, err := syscall.Recvfrom(fd, buf, 0)
				if err != nil {
					return
				}

				frame := make([]byte, n)
				copy(frame, buf[:n])
				out <- frame
			}
		}
	}()

	return out, func() { close(stop) }, nil
}
