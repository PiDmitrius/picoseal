package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/sys/unix"
)

// Segments: "PSE1" + scope + E's private key, and "PSS1" + scope + name
// length + name + the raw bytes of a cryptobox for E, where scope names the
// euid and store directory. The segment key is derived from the scope and the
// name, so a segment is found without an index; that key is public and short,
// so a segment counts only if its owner and creator are the caller, its mode
// is 0600 and its scope and name match. A segment is visible before its creator
// fills it, so the magic is written last and a reader waits briefly for it; a
// segment that never gets one was left by a creator that died.
const (
	magicSession = "PSE1"
	magicSlot    = "PSS1"
	shmLock      = 11 // SHM_LOCK
)

var (
	errNoSession = errors.New("no session key since boot: take a fresh pubkey")
	errExists    = errors.New("already exists")
	errDamaged   = errors.New("damaged")
)

type foreignError struct{}

func (foreignError) Error() string {
	return "a shared memory segment picoseal needs is held by another user"
}

func scope() []byte {
	sum := sha256.Sum256([]byte(fmt.Sprintf("picoseal\x00%d\x00%s", os.Geteuid(), dir)))
	return sum[:8]
}

func segmentKey(kind byte, name string) int {
	sum := sha256.Sum256(append(append(scope(), kind, 0), name...))
	if key := int(int32(binary.BigEndian.Uint32(sum[:]))); key != 0 {
		return key
	}
	return 1
}

// readSegment returns the contents of the caller's segment id.
func readSegment(id int) ([]byte, error) {
	var desc unix.SysvShmDesc
	if _, err := unix.SysvShmCtl(id, unix.IPC_STAT, &desc); errors.Is(err, unix.EACCES) {
		return nil, foreignError{}
	} else if err != nil {
		return nil, err
	}
	uid := uint32(os.Geteuid())
	if desc.Perm.Uid != uid || desc.Perm.Cuid != uid || desc.Perm.Mode&0o777 != 0o600 {
		return nil, foreignError{}
	}
	mem, err := unix.SysvShmAttach(id, 0, unix.SHM_RDONLY)
	if err != nil {
		return nil, err
	}
	defer unix.SysvShmDetach(mem)
	return bytes.Clone(mem), nil
}

func findSegment(key int) (id int, data []byte, err error) {
	id, err = unix.SysvShmGet(key, 0, 0)
	if errors.Is(err, unix.ENOENT) {
		return -1, nil, os.ErrNotExist
	}
	if errors.Is(err, unix.EACCES) {
		return segmentID(key), nil, foreignError{}
	}
	if err != nil {
		return -1, nil, err
	}
	data, err = readSegment(id)
	return id, data, err
}

// createSegment stores data in a new locked segment, or returns os.ErrExist if
// the caller already has one under key. Root clears a segment someone else
// placed there.
func createSegment(key int, data []byte) error {
	id, err := unix.SysvShmGet(key, len(data), unix.IPC_CREAT|unix.IPC_EXCL|0o600)
	if errors.Is(err, unix.EEXIST) || errors.Is(err, unix.EACCES) {
		held, _, err := findSegment(key)
		if err == nil {
			return os.ErrExist
		}
		if !errors.As(err, new(foreignError)) || os.Geteuid() != 0 || held < 0 {
			return err
		}
		if _, rmErr := unix.SysvShmCtl(held, unix.IPC_RMID, nil); rmErr != nil {
			return fmt.Errorf("%w, and clearing it failed: %v", err, rmErr)
		}
		id, err = unix.SysvShmGet(key, len(data), unix.IPC_CREAT|unix.IPC_EXCL|0o600)
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	fail := func(err error) error {
		unix.SysvShmCtl(id, unix.IPC_RMID, nil)
		return err
	}
	if _, err := unix.SysvShmCtl(id, shmLock, nil); err != nil {
		return fail(fmt.Errorf("lock a segment in memory: %w", err))
	}
	mem, err := unix.SysvShmAttach(id, 0, 0)
	if err != nil {
		return fail(err)
	}
	copy(mem[4:], data[4:])
	copy(mem, data[:4])
	return unix.SysvShmDetach(mem)
}

// settled reads the caller's segment under key once its creator has filled it.
func settled(key int) (id int, data []byte, err error) {
	for range 20 {
		if id, data, err = findSegment(key); err != nil || !bytes.Equal(data[:min(4, len(data))], make([]byte, min(4, len(data)))) {
			return id, data, err
		}
		time.Sleep(10 * time.Millisecond)
	}
	return id, data, fmt.Errorf("segment %d is %w", key, errDamaged)
}

// sessionKey returns E, creating it when create is set; root replaces a
// segment someone else placed on its key, and anyone replaces a damaged one.
func sessionKey(create bool) (pub, priv *[32]byte, err error) {
	key := segmentKey('E', "")
	id, data, err := settled(key)
	if err == nil && (len(data) != 4+8+32 || string(data[:4]) != magicSession || !bytes.Equal(data[4:12], scope())) {
		err = fmt.Errorf("segment %d holds something else", key)
	}
	switch {
	case err == nil:
	case !create:
		if errors.Is(err, os.ErrNotExist) {
			err = errNoSession
		}
		return nil, nil, err
	case errors.Is(err, errDamaged) || errors.Is(err, os.ErrNotExist) || errors.As(err, new(foreignError)):
		if errors.Is(err, errDamaged) {
			var desc unix.SysvShmDesc
			if _, err := unix.SysvShmCtl(id, unix.IPC_STAT, &desc); err != nil {
				return nil, nil, err
			}
			if unix.Kill(int(desc.Cpid), 0) != unix.ESRCH {
				return nil, nil, fmt.Errorf("segment %d is still being created by pid %d", key, desc.Cpid)
			}
			if final, err := readSegment(id); err != nil || !bytes.Equal(final[:4], make([]byte, 4)) {
				return sessionKey(false)
			}
			if err := removeSegment(id); err != nil {
				return nil, nil, err
			}
		}
		if _, priv, err = box.GenerateKey(rand.Reader); err != nil {
			return nil, nil, err
		}
		data = append(append([]byte(magicSession), scope()...), priv[:]...)
		if err = createSegment(key, data); errors.Is(err, os.ErrExist) {
			return sessionKey(false)
		}
		if err != nil {
			return nil, nil, err
		}
	default:
		return nil, nil, err
	}
	priv = new([32]byte)
	copy(priv[:], data[12:])
	return publicKey(priv), priv, nil
}

func publicKey(priv *[32]byte) *[32]byte {
	var pub [32]byte
	derived, _ := curve25519.X25519(priv[:], curve25519.Basepoint)
	copy(pub[:], derived)
	return &pub
}

func parseSlot(data []byte) (name string, raw []byte, ok bool) {
	if len(data) < 13 || string(data[:4]) != magicSlot || !bytes.Equal(data[4:12], scope()) || len(data) < 13+int(data[12]) {
		return "", nil, false
	}
	return string(data[13 : 13+data[12]]), data[13+data[12]:], true
}

func storeSlot(name string, value []byte) error {
	pub, _, err := sessionKey(true)
	if err != nil {
		return err
	}
	raw, err := box.SealAnonymous(nil, value, pub, rand.Reader)
	if err != nil {
		return err
	}
	data := append(append([]byte(magicSlot), scope()...), byte(len(name)))
	err = createSegment(segmentKey('S', name), append(append(data, name...), raw...))
	if errors.Is(err, os.ErrExist) {
		return fmt.Errorf("%s %w", name, errExists)
	}
	return err
}

// findSlot returns the id of the slot holding name and its cryptobox; a
// damaged slot comes with its id, so it can be removed.
func findSlot(name string) (int, []byte, error) {
	id, data, err := settled(segmentKey('S', name))
	if err != nil {
		return id, nil, err
	}
	if stored, raw, ok := parseSlot(data); ok && stored == name {
		return id, raw, nil
	}
	return -1, nil, os.ErrNotExist
}

func loadSlot(name string) ([]byte, error) {
	_, raw, err := findSlot(name)
	if err != nil {
		return nil, err
	}
	pub, priv, err := sessionKey(false)
	if err != nil {
		return nil, err
	}
	value, ok := box.OpenAnonymous(nil, raw, pub, priv)
	if !ok {
		return nil, fmt.Errorf("%s: not a cryptobox for the session key", name)
	}
	return value, nil
}

// shmTable returns key, id and owner of every segment in /proc/sysvipc/shm.
func shmTable() ([][3]int, error) {
	f, err := os.Open("/proc/sysvipc/shm")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var table [][3]int
	lines := bufio.NewScanner(f)
	lines.Scan()
	for lines.Scan() {
		fields := strings.Fields(lines.Text())
		if len(fields) < 8 {
			continue
		}
		key, err1 := strconv.Atoi(fields[0])
		id, err2 := strconv.Atoi(fields[1])
		uid, err3 := strconv.Atoi(fields[7])
		if err1 == nil && err2 == nil && err3 == nil {
			table = append(table, [3]int{key, id, uid})
		}
	}
	return table, lines.Err()
}

func segmentID(key int) int {
	table, _ := shmTable()
	for _, row := range table {
		if row[0] == key {
			return row[1]
		}
	}
	return -1
}

// slots maps the names of the caller's slots in this store to segment ids.
func slots() (map[string]int, error) {
	table, err := shmTable()
	if err != nil {
		return nil, err
	}
	found := map[string]int{}
	for _, row := range table {
		if row[2] != os.Geteuid() {
			continue
		}
		data, err := readSegment(row[1])
		if err != nil {
			continue
		}
		if name, _, ok := parseSlot(data); ok && segmentKey('S', name) == row[0] {
			found[name] = row[1]
		}
	}
	return found, nil
}

func removeSegment(id int) error {
	_, err := unix.SysvShmCtl(id, unix.IPC_RMID, nil)
	return err
}
