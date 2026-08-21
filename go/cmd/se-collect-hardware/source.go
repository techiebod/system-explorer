package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
)

// source is the acquisition seam (DESIGN 20; harness/se_harness/replay.py):
// with SE_REPLAY_DIR set, the native documents come from that directory
// instead of the live interface, while the parse, the declared semantics and
// the stream generation run unchanged. The seam is a value chosen at startup,
// not a build flag, so the binary the harness judges is the binary that
// deploys.
//
// This interface is not a request-and-reply like the other collectors': the
// interface is a TREE, so the seam is the four primitives that walk one —
// read a file, list a directory, resolve a link, ask udev about a node. That
// shape is the ruling of 2026-08-19 (DESIGN, adjudication queue): the native
// document for a filesystem is the filesystem transcribed, so a replay
// answers each of these out of the capture and never off the machine
// replaying it.
type source interface {
	// bootID names the boot whose clock every `at` reading belongs to;
	// without it the readings are meaningless (DESIGN 09).
	bootID() (string, error)
	// timens is the CLOCK_BOOTTIME namespace offset — stated, never
	// corrected, by whoever compares it (DESIGN 09).
	timens() int64
	// batch mints the batch id — collector-minted by ruling (appendix C).
	batch() (string, error)
	// declaration is the digest begin carries: the hash of the exact bytes
	// `declare` emits (DESIGN 19).
	declaration() string
	// beginCollection is called immediately before a collection's first
	// native read, and stamp is `at` for the i-th emitted object. Two calls
	// rather than one because a collector reading five trees legitimately has
	// five ages: `at` is stamped before the EARLIEST read that contributes to
	// the object, so the tie breaks toward older (DESIGN 19).
	beginCollection() error
	stamp(i int) float64
	// costs are end's advisory self-report (DESIGN 19).
	costs() (cpuMS, wallMS float64)

	// ── the tree ────────────────────────────────────────────────────
	// read is one file's contents, whitespace-stripped, and whether there
	// was one. An empty file reads as absent, because sysfs spells "not
	// established" as an empty string as often as it spells it as a missing
	// node — the reference's own `read_text().strip() or None`.
	read(p string) (string, bool)
	// listdir is one directory's entries, sorted. A directory that is not
	// there is an empty listing rather than an error: on this interface,
	// "no such class" is an ordinary reading (a host with no NVMe has no
	// /sys/class/nvme) and not a failure to read one.
	listdir(p string) []string
	// readBytes is one file's exact octets, for the single attribute that is
	// BINARY: SCSI VPD page 0x80, whose first four bytes are a header and
	// whose remainder is the drive's serial. A text read would mangle a
	// non-ASCII octet before the slice could drop it.
	//
	// The reference reads this one with a bare Path().read_bytes() and has no
	// seam point for it, so a capture from a host with a scsi disk cannot be
	// replayed faithfully by EITHER implementation today — it would read the
	// tree of whichever machine replays. This side refuses instead, which is
	// the louder half of the same gap; see the reported residual.
	readBytes(p string) ([]byte, bool)
	// exists is whether one attribute is there at all. Its own primitive
	// because for one reading the PROBE is the reading: host_sas_address
	// exists on a SAS host and nowhere else, and its contents are read by
	// nothing.
	exists(p string) bool
	// realpath is where a path lands after every symlink on it is followed,
	// with a component that does not exist left as written — posix
	// realpath's non-strict form, which is what the reference calls.
	realpath(p string) string
	// udev is the hwdb reply for one syspath, flat as `--json=short` emits
	// it. An empty map is the honest answer for a node udev knows nothing
	// about, and it is what the reference publishes too.
	udev(syspath string) map[string]string
	// lscpu is the field table of `lscpu -J`, flattened through its
	// children. The error arm is a NOTE and not a failure: a host without
	// util-linux still has DMI and /proc/meminfo, and the reference catches
	// this exact call.
	lscpu() (map[string]string, error)

	// ── drive health, in the three depths the reference reads ───────
	// smartSnapshot is the root collector's reading for one device and the
	// unix time it was written, if the grantDiskAccess timer is running.
	smartSnapshot(device string) (map[string]json.RawMessage, float64, bool)
	// smartReason is smartctl's own words for why the last run produced no
	// reading — written beside the snapshot so nothing here has to guess.
	smartReason(device string) (string, bool)
	// smartctlJSON is a direct `smartctl --json` run, the fallback for an
	// ad-hoc invocation that happens to hold the access.
	smartctlJSON(devicePath string) (map[string]json.RawMessage, error)
	// smartctlUsable reports whether a direct run is even possible here —
	// the binary on PATH and the node readable. Both are properties of the
	// machine, so both belong behind the seam.
	smartctlUsable(devicePath string) bool
	// drives is udisks2's view, keyed by block-device name, and whether the
	// daemon answered at all. The second value is what keeps the source
	// note truthful about a reading nobody could take.
	drives() (map[string]driveHealth, bool)

	// hostname is the name the platform object is published under — law 1's
	// obligation, the name this machine was observed by. Behind the seam
	// because the object ID is minted from it: an unpinned replay would name
	// the object after whichever machine is REPLAYING, and one capture would
	// produce a different object on every host that read it — silently,
	// because a hostname is a plausible value wherever it came from.
	hostname() string

	// now is wall-clock seconds, for the one fact derived against it: a
	// SMART snapshot's age. Behind the seam because replay pins it
	// (SE_REPLAY_NOW), and a fact derived from an unpinned clock would move
	// every day the corpus sat on the shelf.
	now() float64

	// sysfsAbsent is the one condition that declines: no device tree at all.
	// A property of the source rather than of any walk, because the live
	// answer is whether the kernel mounted /sys and the replay answer is
	// whether the variant staged a tree document — two readings of one
	// condition, which is why they route through one constant below.
	sysfsAbsent() bool

	// failure is the first acquisition this source could not answer, or
	// nil. Under replay it is a path the capture does not hold — never a
	// decline, because a document nobody captured says nothing about any
	// machine, and never a fallback to the live tree, which would be the
	// tree of whichever host is replaying.
	failure() error
}

// sysfsPresent is the decline gate, spelled once for the probe and the
// collect path alike.
func sysfsPresent(src source) error {
	if src.sysfsAbsent() {
		reason := declineNoSysfs
		return &reason
	}
	return nil
}

// declined is the seam's statement that the interface itself could not be
// read, carried as an error so no caller can forget to route it. The detail is
// a constant: decline detail travels to a hub and out over MCP, and an
// interpolated error string is a redaction path nobody reviewed.
type declined struct{ reason, detail string }

func (d *declined) Error() string { return d.reason + ": " + d.detail }

// The interface-is-not-here reading, named ONCE and used by the live source
// and the replay source alike. It is a constant because the storage collector
// answered exactly this question two opposite ways for as long as it existed —
// live said `unsupported`, replay said `absent`, each under a confident comment
// arguing against the other — and nothing caught it, because replay exercises
// only the replay half. A shared constant makes the disagreement unspellable
// rather than merely currently-absent.
//
// `absent` is the reading, and it is the one decline that commits. Every class
// tree this collector walks is mounted by the kernel itself, so a host with
// none of them has no sysfs: a successful reading that establishes something,
// and one that must be able to retire the rows a previous batch published.
//
// ALL of them, never one: a host with no /sys/class/nvme is an ordinary host
// with no NVMe controllers, and this guest is one. Deciding absence on any
// single tree would retire a whole subsystem over a machine that simply has no
// SAS expanders — the direction that destroys data.
//
// The wording is the replay shim's own ("no <interface> on this host"), so the
// two implementations produce the same record for the same condition rather
// than two spellings a reader would take for two conditions.
var declineNoSysfs = declined{"absent", "no sysfs on this host"}

// errUncaptured marks a document the variant did not stage. It must never fall
// back to the live interface of the machine REPLAYING the corpus — that seam
// escape once put a replaying workstation's filesystem into committed facts —
// and it must not become a decline either, which would state something about a
// machine nobody observed.
var errUncaptured = errors.New("not captured in this replay directory")

// The trees this collector walks, and the sysfs paths it reads them from. One
// list, because it is both what the live source probes for absence and what
// the declaration's read_paths must carry.
const (
	pciDevices   = "/sys/bus/pci/devices"
	usbDevices   = "/sys/bus/usb/devices"
	nvmeDevices  = "/sys/class/nvme"
	scsiHosts    = "/sys/class/scsi_host"
	scsiDevices  = "/sys/bus/scsi/devices"
	sasExpanders = "/sys/class/sas_expander"
	sasDevices   = "/sys/class/sas_device"
	sasPhys      = "/sys/class/sas_phy"
	ataLinks     = "/sys/class/ata_link"
	enclosures   = "/sys/class/enclosure"
	byPath       = "/dev/disk/by-path"
	byID         = "/dev/disk/by-id"
	dmi          = "/sys/devices/virtual/dmi/id"
	hwmon        = "/sys/class/hwmon"

	smartSnapshotDir = "/run/system-explorer-smart"
)

// The trees whose simultaneous absence means sysfs itself is not here. DMI is
// in the list because a machine can genuinely have no PCI bus and no USB
// controller — an ARM board does — while every Linux mounts /sys/devices.
var sysfsTrees = []string{pciDevices, usbDevices, scsiHosts, nvmeDevices, dmi}

func newSource(getenv func(string) string) source {
	if dir := getenv("SE_REPLAY_DIR"); dir != "" {
		return newReplaySource(dir, getenv("SE_REPLAY_NOW"))
	}
	return &liveSource{started: time.Now()}
}

// ── live ────────────────────────────────────────────────────────────────

type liveSource struct {
	started time.Time
	at      float64
	err     error

	udisksOnce bool
	udisksMap  map[string]driveHealth
	udisksOK   bool
}

func (*liveSource) bootID() (string, error) {
	raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", fmt.Errorf("boot_id: %v", err)
	}
	return strings.TrimSpace(string(raw)), nil
}

func (*liveSource) timens() int64 { return timensOffset() }

func (*liveSource) batch() (string, error) { return newUUIDv4() }

func (*liveSource) declaration() string { return declarationDigest }

func (s *liveSource) beginCollection() error {
	at, err := bootClock()
	if err != nil {
		return err
	}
	s.at = at
	return nil
}

func (s *liveSource) stamp(int) float64 { return s.at }

func (s *liveSource) costs() (float64, float64) {
	cpu := 0.0
	var usage syscall.Rusage
	// 0 is RUSAGE_SELF on every POSIX platform this compiles for; a failed
	// reading reports zero cost rather than failing the batch, because the
	// self-report is advisory by construction (DESIGN 19).
	if syscall.Getrusage(0, &usage) == nil {
		cpu = float64(usage.Utime.Nano()+usage.Stime.Nano()) / 1e6
	}
	return cpu, float64(time.Since(s.started)) / float64(time.Millisecond)
}

func (s *liveSource) failure() error { return s.err }

// Every one of these trees is mounted by the kernel itself, so a host with
// none of them has no sysfs. All of them, never one: a host with no
// /sys/class/nvme is an ordinary host with no NVMe controllers.
func (*liveSource) sysfsAbsent() bool {
	for _, tree := range sysfsTrees {
		if info, err := os.Stat(tree); err == nil && info.IsDir() {
			return false
		}
	}
	return true
}

func (*liveSource) now() float64 { return float64(time.Now().UnixNano()) / 1e9 }

func (*liveSource) hostname() string {
	name, err := os.Hostname()
	if err != nil {
		return ""
	}
	// The SHORT name, as the reference takes it: a machine whose kernel
	// hostname carries a domain is the same machine, and the two spellings
	// would key the collator on two objects.
	return strings.SplitN(name, ".", 2)[0]
}

func (*liveSource) read(p string) (string, bool) {
	raw, err := os.ReadFile(p)
	if err != nil {
		return "", false
	}
	value := strings.TrimSpace(string(raw))
	return value, value != ""
}

func (*liveSource) listdir(p string) []string {
	entries, err := os.ReadDir(p)
	if err != nil {
		return []string{}
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names
}

func (*liveSource) readBytes(p string) ([]byte, bool) {
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, false
	}
	return raw, true
}

func (*liveSource) exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

func (*liveSource) realpath(p string) string { return resolve(p) }

// The bound on one native command. Every one of these is a local read of a
// kernel interface; a tool that has not answered in this long has hung, and a
// sweep must not hang with it.
const commandTimeout = 20 * time.Second

func (*liveSource) udev(syspath string) map[string]string {
	out, err := runCommand(commandTimeout, "udevadm", "info", "--json=short", syspath)
	if err != nil {
		// A node udev cannot describe is an ordinary reading here — the
		// caller publishes the facts it can and no others — so this is empty
		// rather than fatal, exactly as the reference's returncode check is.
		return map[string]string{}
	}
	properties := map[string]string{}
	if err := json.Unmarshal(out, &properties); err != nil {
		return map[string]string{}
	}
	return properties
}

func (*liveSource) lscpu() (map[string]string, error) {
	out, err := runCommand(commandTimeout, "lscpu", "-J")
	if err != nil {
		return nil, err
	}
	return lscpuFields(out)
}

func (*liveSource) smartSnapshot(device string) (map[string]json.RawMessage, float64, bool) {
	p := filepath.Join(smartSnapshotDir, device+".json")
	info, err := os.Stat(p)
	if err != nil {
		return nil, 0, false
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, 0, false
	}
	document := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, 0, false
	}
	return document, float64(info.ModTime().UnixNano()) / 1e9, true
}

func (*liveSource) smartReason(device string) (string, bool) {
	raw, err := os.ReadFile(filepath.Join(smartSnapshotDir, device+".reason"))
	if err != nil {
		return "", false
	}
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return "", false
	}
	return boundedReason(text), true
}

// The one command this collector ever RUNS against a device rather than
// reading about it, and only where the deployment granted the access. NVMe
// nodes need the type stated: auto-detection fails on ng/controller devices.
var nvmeNode = regexp.MustCompile(`^/dev/(ng|nvme)\d`)

func (*liveSource) smartctlJSON(devicePath string) (map[string]json.RawMessage, error) {
	argv := []string{"smartctl", "--json=c", "-H", "-A", devicePath}
	if nvmeNode.MatchString(devicePath) {
		argv = append(argv[:1], append([]string{"-d", "nvme"}, argv[1:]...)...)
	}
	// smartctl's exit codes are a BITMASK that flags drive problems while the
	// JSON stays valid, so the output is parsed whatever the status — a
	// collector that required rc 0 would go blind exactly on the drives worth
	// looking at.
	out, _ := runCommandIgnoringStatus(commandTimeout, argv[0], argv[1:]...)
	document := map[string]json.RawMessage{}
	if len(out) == 0 {
		return document, nil
	}
	if err := json.Unmarshal(out, &document); err != nil {
		return nil, err
	}
	return document, nil
}

func (*liveSource) smartctlUsable(devicePath string) bool {
	if _, err := exec.LookPath("smartctl"); err != nil {
		return false
	}
	return syscall.Access(devicePath, 4 /* R_OK */) == nil
}

// ── replay ──────────────────────────────────────────────────────────────

// A replay has no boot, so the fixed v4-shaped id — "5e" up front so no reader
// mistakes it for a capture. The shape rule refuses the old "replay" stub and
// the nil UUID; that this constant itself passes is DESIGN 19's named
// deferral, the live comparator's to catch.
const replayBootID = "5e000000-0000-4000-8000-000000000001"

// The payload each primitive's document is committed under. The stems are the
// replay seam's own addressing (harness/bin/se-reference-collector), so a
// reviewer reading a file name is reading which primitive it answers.
const (
	payloadRead          = "read.json"
	payloadReadBytes     = "read-bytes.json"
	payloadListdir       = "listdir.json"
	payloadRealpath      = "realpath.json"
	payloadExists        = "exists.json"
	payloadUdev          = "udev.json"
	payloadLscpu         = "lscpu.json"
	payloadSmartctl      = "smartctl.json"
	payloadSmartSnapshot = "smart-snapshot.json"
	payloadSmartReason   = "smart-reason.json"
	// Text, not JSON: the kernel hostname IS the document (DESIGN 20), and
	// the replay seam serves it verbatim.
	payloadHostname = "hostname"
)

type replaySource struct {
	dir string

	read_ map[string]map[string]*string
	// Base64, because a payload is JSON and these octets are not text. The
	// DECODE stays here rather than in the seam, so the parse the port has to
	// reproduce is still the port's.
	readBytes_ map[string]map[string]*string
	listdir_   map[string]map[string][]string
	realpath_  map[string]map[string]string
	exists_    map[string]map[string]bool
	udev_      map[string]map[string]map[string]string

	// The three smart maps stay raw: a snapshot's document is a JSON object
	// whose numbers must reach the wire spelled exactly as smartctl wrote
	// them (DESIGN 19's pass-through ruling), and a re-encode through any Go
	// numeric type would respell them.
	smartctl_ map[string]map[string]json.RawMessage
	snapshot_ map[string]map[string]json.RawMessage
	reason_   map[string]map[string]*string

	lscpuRaw  []byte
	hostname_ string
	staged    bool // any tree document at all was captured

	pinned float64
	err    error
}

func newReplaySource(dir, replayNow string) *replaySource {
	r := &replaySource{dir: dir}
	// Every document is loaded, and `staged` is true if ANY of them was
	// there — the || would short-circuit if the calls were inline, so each
	// runs first and the disjunction is taken afterwards.
	haveRead := loadPayload(r, payloadRead, &r.read_)
	haveReadBytes := loadPayload(r, payloadReadBytes, &r.readBytes_)
	haveListdir := loadPayload(r, payloadListdir, &r.listdir_)
	haveRealpath := loadPayload(r, payloadRealpath, &r.realpath_)
	haveExists := loadPayload(r, payloadExists, &r.exists_)
	haveUdev := loadPayload(r, payloadUdev, &r.udev_)
	r.staged = haveRead || haveReadBytes || haveListdir || haveRealpath ||
		haveExists || haveUdev
	loadPayload(r, payloadSmartctl, &r.smartctl_)
	loadPayload(r, payloadSmartSnapshot, &r.snapshot_)
	loadPayload(r, payloadSmartReason, &r.reason_)
	if raw, err := os.ReadFile(filepath.Join(dir, payloadLscpu)); err == nil {
		r.lscpuRaw = raw
	}
	if raw, err := os.ReadFile(filepath.Join(dir, payloadHostname)); err == nil {
		r.hostname_ = strings.TrimSpace(string(raw))
	}
	// SE_REPLAY_NOW freezes the one clock a fact is derived against, so a
	// snapshot's age is the same number on every machine that replays and on
	// every day it is replayed. Unpinned, the live clock stands — the same
	// choice the reference makes, and the corpus pins it.
	if replayNow != "" {
		if moment, err := time.Parse(time.RFC3339, strings.Replace(replayNow, "Z", "+00:00", 1)); err == nil {
			r.pinned = float64(moment.UnixNano()) / 1e9
		}
	}
	return r
}

// loadPayload decodes one captured document, reporting whether it was there.
// A file that is present and unreadable is a broken capture and fails the
// batch; a file that is absent is a primitive this variant never exercised,
// and every call to it will refuse.
func loadPayload[T any](r *replaySource, name string, into *T) bool {
	raw, err := os.ReadFile(filepath.Join(r.dir, name))
	if err != nil {
		return false
	}
	if err := json.Unmarshal(raw, into); err != nil {
		r.fail(fmt.Errorf("payload %s: %v", name, err))
		return false
	}
	return true
}

func (r *replaySource) fail(err error) {
	if r.err == nil {
		r.err = err
	}
}

func (r *replaySource) uncaptured(primitive, argument string) {
	r.fail(fmt.Errorf("%s %q %w; the tree seam refuses to read the filesystem of the machine replaying the corpus",
		primitive, argument, errUncaptured))
}

func (r *replaySource) failure() error { return r.err }

// The replay half of the same condition: a variant that staged no tree
// document at all is a capture of a host with no sysfs, which is what the
// shim's own "no document was captured" rule says.
func (r *replaySource) sysfsAbsent() bool { return !r.staged }

func (r *replaySource) bootID() (string, error) { return replayBootID, nil }

// No time namespace was observed at capture, so the offset is the pinned zero
// — a live reading here would smuggle the replaying machine into a
// deterministic stream.
func (*replaySource) timens() int64 { return 0 }

func (*replaySource) batch() (string, error) { return "replay", nil }

// The real digest, under replay as much as live: the declaration identifies
// THIS collector's contract, and a replay does not change which contract this
// binary holds.
func (*replaySource) declaration() string { return declarationDigest }

// Nothing to stamp: under replay `at` is the index formula below, so there is
// no clock to read before a collection's first document.
func (*replaySource) beginCollection() error { return nil }

func (*replaySource) stamp(i int) float64 {
	// The reference constant, 1.0 + 0.001*i in emission order and one counter
	// across the whole batch: finite, positive, boot-scale and advancing, so
	// the structural rule that governs `at` is exercised by replay instead of
	// satisfied by a hardcoded zero. Rounded because the reference rounds.
	return float64(int64((1.0+0.001*float64(i))*1000+0.5)) / 1000
}

func (*replaySource) costs() (float64, float64) { return 0.5, 1.0 }

// The name the capture was taken under, so one pair produces one object on
// every machine that replays it. Empty when the variant staged none, which is
// what the absent-interface variant is.
func (r *replaySource) hostname() string { return r.hostname_ }

func (r *replaySource) now() float64 {
	if r.pinned != 0 {
		return r.pinned
	}
	return float64(time.Now().UnixNano()) / 1e9
}

// split is the tree seam's addressing: the directory, then the name inside it.
// It is how the capture is keyed and how a reviewer reads it back — one object
// per directory, `cat`-able against the guest a line at a time.
func split(p string) (string, string) {
	return path.Dir(p), path.Base(p)
}

// A path with no directory part at all — a device NAME, which is how the
// smartctl snapshot files are addressed — lands under the empty container, so
// the capture stays one shape.
func splitArgument(argument string) (string, string) {
	cut := strings.LastIndex(argument, "/")
	if cut < 0 {
		return "", argument
	}
	return argument[:cut], argument[cut+1:]
}

func (r *replaySource) read(p string) (string, bool) {
	container, member := splitArgument(p)
	inside, ok := r.read_[container]
	if !ok {
		r.uncaptured("read", p)
		return "", false
	}
	value, ok := inside[member]
	if !ok {
		r.uncaptured("read", p)
		return "", false
	}
	// A captured null is the interface's own "there is no such file", which
	// on a sysfs walk is an ORDINARY reading: six firmware attribute names
	// are tried per scsi host and at most one exists. It is a captured
	// answer, not an uncaptured one, and the difference is the whole reason
	// the nulls are recorded.
	if value == nil {
		return "", false
	}
	return *value, true
}

func (r *replaySource) listdir(p string) []string {
	container, member := splitArgument(p)
	inside, ok := r.listdir_[container]
	if !ok {
		r.uncaptured("listdir", p)
		return []string{}
	}
	entries, ok := inside[member]
	if !ok {
		r.uncaptured("listdir", p)
		return []string{}
	}
	if entries == nil {
		return []string{}
	}
	return entries
}

// One binary attribute out of the capture, decoded from the base64 the
// reference's own primitive transcribes it as. Until 2026-08-21 this refused
// every call, because the reference read VPD page 0x80 through an inline
// Path.read_bytes with no seam point — so no variant could hold one, and the
// first capture with a real SCSI disk was unreplayable. A null is a captured
// answer (the attribute is not there, which is ordinary), a path the document
// does not hold is uncaptured and refuses.
func (r *replaySource) readBytes(p string) ([]byte, bool) {
	container, member := splitArgument(p)
	inside, ok := r.readBytes_[container]
	if !ok {
		r.uncaptured("read-bytes", p)
		return nil, false
	}
	encoded, ok := inside[member]
	if !ok {
		r.uncaptured("read-bytes", p)
		return nil, false
	}
	if encoded == nil {
		return nil, false
	}
	raw, err := base64.StdEncoding.DecodeString(*encoded)
	if err != nil {
		r.fail(fmt.Errorf("payload %s: %s is not base64: %v", payloadReadBytes, p, err))
		return nil, false
	}
	return raw, true
}

func (r *replaySource) exists(p string) bool {
	container, member := splitArgument(p)
	inside, ok := r.exists_[container]
	if !ok {
		r.uncaptured("exists", p)
		return false
	}
	present, ok := inside[member]
	if !ok {
		r.uncaptured("exists", p)
		return false
	}
	return present
}

func (r *replaySource) realpath(p string) string {
	container, member := splitArgument(p)
	inside, ok := r.realpath_[container]
	if !ok {
		r.uncaptured("realpath", p)
		return p
	}
	resolved, ok := inside[member]
	if !ok {
		r.uncaptured("realpath", p)
		return p
	}
	return resolved
}

func (r *replaySource) udev(syspath string) map[string]string {
	container, member := splitArgument(syspath)
	inside, ok := r.udev_[container]
	if !ok {
		r.uncaptured("udev", syspath)
		return map[string]string{}
	}
	properties, ok := inside[member]
	if !ok {
		r.uncaptured("udev", syspath)
		return map[string]string{}
	}
	return properties
}

func (r *replaySource) lscpu() (map[string]string, error) {
	if r.lscpuRaw == nil {
		// The reference's own degradation, not a batch failure: its lscpu
		// stub raises and _platform_observation catches, so a variant with no
		// lscpu document publishes a platform row with DMI and memory and no
		// CPU facts. Reproduced rather than improved on.
		return nil, fmt.Errorf("%s %w", payloadLscpu, errUncaptured)
	}
	return lscpuFields(r.lscpuRaw)
}

func (r *replaySource) smartSnapshot(device string) (map[string]json.RawMessage, float64, bool) {
	_, member := splitArgument(device)
	inside, ok := r.snapshot_[""]
	if !ok {
		r.uncaptured("smart snapshot", device)
		return nil, 0, false
	}
	raw, ok := inside[member]
	if !ok {
		r.uncaptured("smart snapshot", device)
		return nil, 0, false
	}
	// The capture records what the reference returns: a [document, mtime]
	// pair, or null where there is no snapshot.
	var pair []json.RawMessage
	if err := json.Unmarshal(raw, &pair); err != nil || len(pair) != 2 {
		return nil, 0, false
	}
	document := map[string]json.RawMessage{}
	var mtime float64
	if json.Unmarshal(pair[0], &document) != nil || json.Unmarshal(pair[1], &mtime) != nil {
		return nil, 0, false
	}
	return document, mtime, true
}

func (r *replaySource) smartReason(device string) (string, bool) {
	_, member := splitArgument(device)
	inside, ok := r.reason_[""]
	if !ok {
		r.uncaptured("smart reason", device)
		return "", false
	}
	value, ok := inside[member]
	if !ok {
		r.uncaptured("smart reason", device)
		return "", false
	}
	if value == nil {
		return "", false
	}
	return *value, true
}

func (r *replaySource) smartctlJSON(devicePath string) (map[string]json.RawMessage, error) {
	container, member := splitArgument(devicePath)
	inside, ok := r.smartctl_[container]
	if !ok {
		return nil, fmt.Errorf("smartctl %q %w", devicePath, errUncaptured)
	}
	raw, ok := inside[member]
	if !ok {
		return nil, fmt.Errorf("smartctl %q %w", devicePath, errUncaptured)
	}
	document := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, err
	}
	return document, nil
}

// Under replay a direct run is always possible in principle — the payload
// decides whether a document comes back — because whether the binary is on
// the PATH of the machine REPLAYING says nothing about the machine captured.
// The reference is stubbed at the same point.
func (*replaySource) smartctlUsable(string) bool { return true }

func (r *replaySource) drives() (map[string]driveHealth, bool) {
	// No committed variant carries a udisks2 document, and refusing is the
	// reading rather than a gap: the reference's replay seam installs a bus
	// that raises, its _drive_health catches, and the row it builds is the
	// row a host with no udisks2 on the bus produces. Dialling the system bus
	// of whichever machine is replaying is the one thing this must never do.
	return nil, false
}

// ── shared ──────────────────────────────────────────────────────────────

// resolve is posix realpath's non-strict form: every symlink on the path is
// followed, and a component that does not exist is left exactly as written.
//
// The non-strict half is load-bearing rather than a convenience. The reference
// calls os.path.realpath, which answers for a missing path instead of raising,
// and the walk downstream reads TOPOLOGY out of the answer — an `ataN`
// segment means SATA, a PCI function means the adapter this hangs from. A
// resolver that errored on a missing component would publish a host with
// neither, which is a wrong answer wearing a complete one's clothes.
func resolve(p string) string {
	if !filepath.IsAbs(p) {
		if wd, err := os.Getwd(); err == nil {
			p = filepath.Join(wd, p)
		}
	}
	resolved := "/"
	// A cap on link chases, because a symlink loop is a real filesystem state
	// and an uncapped walk is a hang. posix uses ELOOP for the same reason.
	const maxLinks = 40
	links := 0
	rest := strings.Split(path.Clean(p), "/")
	for len(rest) > 0 {
		name := rest[0]
		rest = rest[1:]
		if name == "" || name == "." {
			continue
		}
		if name == ".." {
			resolved = path.Dir(resolved)
			continue
		}
		candidate := path.Join(resolved, name)
		target, err := os.Readlink(candidate)
		if err != nil || links >= maxLinks {
			resolved = candidate
			continue
		}
		links++
		if path.IsAbs(target) {
			resolved = "/"
			rest = append(strings.Split(path.Clean(target), "/"), rest...)
		} else {
			rest = append(strings.Split(path.Clean(target), "/"), rest...)
		}
	}
	return resolved
}

// lscpuFields flattens `lscpu -J` into {field name without its colon: data},
// walking children so the cache and vulnerability tables land in the same map
// their parents do — which is where the reference reads them from.
func lscpuFields(raw []byte) (map[string]string, error) {
	var document struct {
		Lscpu []lscpuEntry `json:"lscpu"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, err
	}
	fields := map[string]string{}
	var walk func(entries []lscpuEntry)
	walk = func(entries []lscpuEntry) {
		for _, entry := range entries {
			if entry.Field != "" && entry.Data != nil {
				fields[strings.TrimRight(entry.Field, ":")] = *entry.Data
			}
			walk(entry.Children)
		}
	}
	walk(document.Lscpu)
	return fields, nil
}

type lscpuEntry struct {
	Field    string       `json:"field"`
	Data     *string      `json:"data"`
	Children []lscpuEntry `json:"children"`
}

func runCommand(timeout time.Duration, name string, args ...string) ([]byte, error) {
	out, err := runCommandIgnoringStatus(timeout, name, args...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// runCommandIgnoringStatus returns whatever the command wrote on stdout and
// reports only the failures that mean nothing came back — the binary missing,
// the timeout. A non-zero status is the caller's to interpret, because for
// smartctl it is a bitmask about the DRIVE rather than about the run.
func runCommandIgnoringStatus(timeout time.Duration, name string, args ...string) ([]byte, error) {
	if _, err := exec.LookPath(name); err != nil {
		return nil, err
	}
	cmd := exec.Command(name, args...)
	// stderr is deliberately dropped rather than captured into any record:
	// a native tool's diagnostics are not payload, and the one channel they
	// must never reach is a fact or a decline detail (DESIGN 19).
	cmd.Stderr = nil
	done := make(chan struct{})
	var out []byte
	var err error
	go func() {
		out, err = cmd.Output()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		<-done
		return nil, fmt.Errorf("%s did not answer within %s", name, timeout)
	}
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return out, err
		}
		return nil, err
	}
	return out, nil
}

// The bound and the scrub every reason text takes before it can travel
// (system_explorer.text): one line, cut on a word boundary at 400 characters,
// with URL query strings and userinfo removed. Failure text reaches a hub and
// goes out over MCP, and one of this estate's planned upstreams accepts its
// API key only as a query parameter — so a single error string is a credential
// channel.
//
// The reference ALSO substitutes the values of *_TOKEN, *_API_KEY, *_SECRET
// and *_PASSWORD environment variables here. That half is deliberately not
// ported: a replayed collector's output must be a function of its payload
// alone, and reading ambient environment makes two machines replaying one
// capture emit different bytes (DESIGN, adjudication queue, "the residue
// scrubber may not read ambient environment").
const reasonLimit = 400

var (
	queryString = regexp.MustCompile(`\?[^\s"'<>]+`)
	urlUserinfo = regexp.MustCompile(`://[^/\s"'<>@]+@`)
)

func boundedReason(value string) string {
	flat := strings.Join(strings.Fields(value), " ")
	if len(flat) > reasonLimit {
		head := flat[:reasonLimit]
		if cut := strings.LastIndex(head, " "); cut > 0 {
			head = head[:cut]
		}
		flat = strings.TrimRight(head, " ,;:.([{-") + " … (truncated)"
	}
	flat = queryString.ReplaceAllString(flat, "?[query-stripped]")
	flat = urlUserinfo.ReplaceAllString(flat, "://[userinfo-stripped]@")
	return flat
}

// newUUIDv4 mints a lowercase RFC 4122 v4 id from the kernel's CSPRNG. No
// dependency: sixteen random bytes with the version and variant bits set is
// the whole format, and this binary stays stdlib-only and static.
func newUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("minting the batch id: %v", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

type probeVerdict struct {
	Verdict string `json:"verdict"`
	Reason  string `json:"reason"`
}

// probe answers "can it run here" as a verdict, never an exit code (DESIGN
// 18). The question this collector's probe asks is the one its decline turns
// on: is sysfs here at all. It is not "is there hardware" — a host with no
// NVMe and no SAS is an ordinary host and this collector reads it fine.
func probe(stdout, stderr io.Writer, src source) int {
	verdict := probeVerdict{Verdict: "yes", Reason: "sysfs is mounted and its device trees are readable"}
	if err := sysfsPresent(src); err != nil {
		var refused *declined
		reason := "sysfs could not be read"
		if errors.As(err, &refused) {
			reason = refused.detail
		}
		verdict = probeVerdict{Verdict: "no", Reason: reason}
		fmt.Fprintln(stderr, "probe:", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(verdict); err != nil {
		fmt.Fprintln(stderr, "writing the probe verdict:", err)
		return exitRuntime
	}
	return exitOK
}
