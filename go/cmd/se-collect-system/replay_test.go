package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const healthyOsRelease = "ID=debian\nVERSION_ID=\"12\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n"

// stageReplayDir lays out the documents the replay seam reads: os-release
// and hostname as raw text, boot_id optional (empty string stages none, so
// the fallback path is reachable).
func stageReplayDir(t *testing.T, osRelease, hostname, bootID string) string {
	t.Helper()
	dir := t.TempDir()
	stage := func(name, content string) {
		if content == "" {
			return
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	stage("os-release", osRelease)
	stage("hostname", hostname)
	stage("boot_id", bootID)
	// hostname1 and machine-id, staged from 2026-08-23 when identity
	// gained the facts the reference had always emitted. A replay
	// directory without them is a capture that PREDATES those facts, and
	// the seam refuses it rather than letting an old capture assert that
	// a machine has no machine-id — so these tests stage them like any
	// other document the collection reads.
	stage("bus.json", stagedBus)
	stage("machine-id", "5cb0781a58ccba61e64e3c90732537cb\n")
	return dir
}

// stagedBus is one captured hostname1 reply, anonymised: the host names
// are the corpus's and the machine-id is its crafted 5cb0 convention,
// while the hardware strings stay as QEMU reported them because they
// describe a hypervisor rather than this estate.
const stagedBus = `{"/org/freedesktop/hostname1 org.freedesktop.DBus.Properties GetAll s org.freedesktop.hostname1":{"type":"a{sv}","data":[{"Hostname":{"type":"s","data":"corpus-host"},"StaticHostname":{"type":"s","data":"corpus-host"},"PrettyHostname":{"type":"s","data":""},"DefaultHostname":{"type":"s","data":"localhost"},"HostnameSource":{"type":"s","data":"static"},"IconName":{"type":"s","data":"computer-vm"},"Chassis":{"type":"s","data":"vm"},"Deployment":{"type":"s","data":""},"Location":{"type":"s","data":""},"KernelName":{"type":"s","data":"Linux"},"KernelRelease":{"type":"s","data":"7.0.0-28-generic"},"KernelVersion":{"type":"s","data":"#28-Ubuntu SMP PREEMPT_DYNAMIC Sun Jun 21 01:01:36 UTC 2026"},"OperatingSystemPrettyName":{"type":"s","data":"Ubuntu 26.04 LTS"},"OperatingSystemCPEName":{"type":"s","data":""},"OperatingSystemSupportEnd":{"type":"t","data":18446744073709551615},"HomeURL":{"type":"s","data":"https://www.ubuntu.com/"},"OperatingSystemImageID":{"type":"s","data":""},"OperatingSystemImageVersion":{"type":"s","data":""},"HardwareVendor":{"type":"s","data":"QEMU"},"HardwareModel":{"type":"s","data":"Standard PC _i440FX + PIIX, 1996_"},"HardwareSKU":{"type":"s","data":""},"HardwareVersion":{"type":"s","data":"pc-i440fx-10.2"},"FirmwareVersion":{"type":"s","data":"edk2-stable202408-prebuilt.qemu.org"},"FirmwareVendor":{"type":"s","data":"EDK II"},"FirmwareDate":{"type":"t","data":1723507200000000},"MachineID":{"type":"ay","data":[92,176,120,26,88,204,186,97,230,78,60,144,115,37,55,203]},"BootID":{"type":"ay","data":[57,193,215,118,85,130,75,237,149,94,129,226,220,31,110,92]},"VSockCID":{"type":"u","data":4294967295},"ChassisAssetTag":{"type":"s","data":""}}]},"/org/freedesktop/systemd1 org.freedesktop.DBus.Properties GetAll s org.freedesktop.systemd1.Manager":{"type":"a{sv}","data":[{"Version":{"type":"s","data":"259.5-0ubuntu3.4"},"Features":{"type":"s","data":"+PAM +AUDIT +SELINUX +APPARMOR +IMA +IPE +SMACK +SECCOMP +GCRYPT -GNUTLS +OPENSSL +ACL +BLKID +CURL +ELFUTILS +FIDO2 +IDN2 -IDN +KMOD +LIBCRYPTSETUP +LIBCRYPTSETUP_PLUGINS +LIBFDISK +PCRE2 +PWQUALITY +P11KIT +QRENCODE +TPM2 +BZIP2 +LZ4 +XZ +ZLIB +ZSTD +BPF_FRAMEWORK +BTF -XKBCOMMON -UTMP +SYSVINIT +LIBARCHIVE"},"Virtualization":{"type":"s","data":"kvm"},"ConfidentialVirtualization":{"type":"s","data":""},"Architecture":{"type":"s","data":"x86-64"},"Tainted":{"type":"s","data":"unmerged-bin"},"FirmwareTimestamp":{"type":"t","data":0},"FirmwareTimestampMonotonic":{"type":"t","data":0},"LoaderTimestamp":{"type":"t","data":0},"LoaderTimestampMonotonic":{"type":"t","data":0},"KernelTimestamp":{"type":"t","data":1787323034149251},"KernelTimestampMonotonic":{"type":"t","data":0},"InitRDTimestamp":{"type":"t","data":1787323034554851},"InitRDTimestampMonotonic":{"type":"t","data":405599},"UserspaceTimestamp":{"type":"t","data":1787323036761417},"UserspaceTimestampMonotonic":{"type":"t","data":2612165},"FinishTimestamp":{"type":"t","data":1787323044099642},"FinishTimestampMonotonic":{"type":"t","data":9950390},"ShutdownStartTimestamp":{"type":"t","data":0},"ShutdownStartTimestampMonotonic":{"type":"t","data":0},"SecurityStartTimestamp":{"type":"t","data":1787323036761597},"SecurityStartTimestampMonotonic":{"type":"t","data":2612345},"SecurityFinishTimestamp":{"type":"t","data":1787323036764818},"SecurityFinishTimestampMonotonic":{"type":"t","data":2615566},"GeneratorsStartTimestamp":{"type":"t","data":1787323037574242},"GeneratorsStartTimestampMonotonic":{"type":"t","data":3424990},"GeneratorsFinishTimestamp":{"type":"t","data":1787323037641900},"GeneratorsFinishTimestampMonotonic":{"type":"t","data":3492649},"UnitsLoadStartTimestamp":{"type":"t","data":1787323037641904},"UnitsLoadStartTimestampMonotonic":{"type":"t","data":3492652},"UnitsLoadFinishTimestamp":{"type":"t","data":1787323037746546},"UnitsLoadFinishTimestampMonotonic":{"type":"t","data":3597295},"UnitsLoadTimestamp":{"type":"t","data":1787466205564921},"UnitsLoadTimestampMonotonic":{"type":"t","data":143169898560},"InitRDSecurityStartTimestamp":{"type":"t","data":1787323034555238},"InitRDSecurityStartTimestampMonotonic":{"type":"t","data":405986},"InitRDSecurityFinishTimestamp":{"type":"t","data":1787323034555317},"InitRDSecurityFinishTimestampMonotonic":{"type":"t","data":406065},"InitRDGeneratorsStartTimestamp":{"type":"t","data":1787323035304406},"InitRDGeneratorsStartTimestampMonotonic":{"type":"t","data":1155154},"InitRDGeneratorsFinishTimestamp":{"type":"t","data":1787323035326919},"InitRDGeneratorsFinishTimestampMonotonic":{"type":"t","data":1177667},"InitRDUnitsLoadStartTimestamp":{"type":"t","data":1787323035326928},"InitRDUnitsLoadStartTimestampMonotonic":{"type":"t","data":1177676},"InitRDUnitsLoadFinishTimestamp":{"type":"t","data":1787323035339381},"InitRDUnitsLoadFinishTimestampMonotonic":{"type":"t","data":1190129},"LogLevel":{"type":"s","data":"info"},"LogTarget":{"type":"s","data":"journal-or-kmsg"},"NNames":{"type":"u","data":532},"NFailedUnits":{"type":"u","data":0},"NJobs":{"type":"u","data":0},"NInstalledJobs":{"type":"u","data":1605},"NFailedJobs":{"type":"u","data":0},"TransactionsWithOrderingCycle":{"type":"at","data":[]},"Progress":{"type":"d","data":1.0},"Environment":{"type":"as","data":["LANG=\u00abredacted\u00bb","PATH=\u00abredacted\u00bb"]},"ConfirmSpawn":{"type":"b","data":false},"ShowStatus":{"type":"b","data":true},"UnitPath":{"type":"as","data":["/etc/systemd/system.control","/run/systemd/system.control","/run/systemd/transient","/run/systemd/generator.early","/etc/systemd/system","/etc/systemd/system.attached","/run/systemd/system","/run/systemd/system.attached","/run/systemd/generator","/usr/local/lib/systemd/system","/usr/lib/systemd/system","/run/systemd/generator.late"]},"DefaultStandardOutput":{"type":"s","data":"journal"},"DefaultStandardError":{"type":"s","data":"inherit"},"WatchdogDevice":{"type":"s","data":""},"WatchdogLastPingTimestamp":{"type":"t","data":18446744073709551615},"WatchdogLastPingTimestampMonotonic":{"type":"t","data":18446744073709551615},"RuntimeWatchdogUSec":{"type":"t","data":0},"RuntimeWatchdogPreUSec":{"type":"t","data":0},"RuntimeWatchdogPreGovernor":{"type":"s","data":""},"RebootWatchdogUSec":{"type":"t","data":600000000},"KExecWatchdogUSec":{"type":"t","data":0},"ServiceWatchdogs":{"type":"b","data":true},"ControlGroup":{"type":"s","data":""},"SystemState":{"type":"s","data":"running"},"ExitCode":{"type":"y","data":0},"DefaultTimerAccuracyUSec":{"type":"t","data":60000000},"DefaultTimeoutStartUSec":{"type":"t","data":90000000},"DefaultTimeoutStopUSec":{"type":"t","data":90000000},"DefaultTimeoutAbortUSec":{"type":"t","data":90000000},"DefaultDeviceTimeoutUSec":{"type":"t","data":90000000},"DefaultRestartUSec":{"type":"t","data":100000},"DefaultStartLimitIntervalUSec":{"type":"t","data":10000000},"DefaultStartLimitBurst":{"type":"u","data":5},"DefaultIOAccounting":{"type":"b","data":false},"DefaultIPAccounting":{"type":"b","data":false},"DefaultMemoryAccounting":{"type":"b","data":true},"DefaultTasksAccounting":{"type":"b","data":true},"DefaultLimitCPU":{"type":"t","data":18446744073709551615},"DefaultLimitCPUSoft":{"type":"t","data":18446744073709551615},"DefaultLimitFSIZE":{"type":"t","data":18446744073709551615},"DefaultLimitFSIZESoft":{"type":"t","data":18446744073709551615},"DefaultLimitDATA":{"type":"t","data":18446744073709551615},"DefaultLimitDATASoft":{"type":"t","data":18446744073709551615},"DefaultLimitSTACK":{"type":"t","data":18446744073709551615},"DefaultLimitSTACKSoft":{"type":"t","data":8388608},"DefaultLimitCORE":{"type":"t","data":18446744073709551615},"DefaultLimitCORESoft":{"type":"t","data":0},"DefaultLimitRSS":{"type":"t","data":18446744073709551615},"DefaultLimitRSSSoft":{"type":"t","data":18446744073709551615},"DefaultLimitNOFILE":{"type":"t","data":524288},"DefaultLimitNOFILESoft":{"type":"t","data":1024},"DefaultLimitAS":{"type":"t","data":18446744073709551615},"DefaultLimitASSoft":{"type":"t","data":18446744073709551615},"DefaultLimitNPROC":{"type":"t","data":4979},"DefaultLimitNPROCSoft":{"type":"t","data":4979},"DefaultLimitMEMLOCK":{"type":"t","data":8388608},"DefaultLimitMEMLOCKSoft":{"type":"t","data":8388608},"DefaultLimitLOCKS":{"type":"t","data":18446744073709551615},"DefaultLimitLOCKSSoft":{"type":"t","data":18446744073709551615},"DefaultLimitSIGPENDING":{"type":"t","data":4979},"DefaultLimitSIGPENDINGSoft":{"type":"t","data":4979},"DefaultLimitMSGQUEUE":{"type":"t","data":819200},"DefaultLimitMSGQUEUESoft":{"type":"t","data":819200},"DefaultLimitNICE":{"type":"t","data":0},"DefaultLimitNICESoft":{"type":"t","data":0},"DefaultLimitRTPRIO":{"type":"t","data":0},"DefaultLimitRTPRIOSoft":{"type":"t","data":0},"DefaultLimitRTTIME":{"type":"t","data":18446744073709551615},"DefaultLimitRTTIMESoft":{"type":"t","data":18446744073709551615},"DefaultTasksMax":{"type":"t","data":1493},"DefaultMemoryPressureThresholdUSec":{"type":"t","data":200000},"DefaultMemoryPressureWatch":{"type":"s","data":"auto"},"TimerSlackNSec":{"type":"t","data":50000},"DefaultOOMPolicy":{"type":"s","data":"stop"},"DefaultOOMScoreAdjust":{"type":"i","data":0},"DefaultRestrictSUIDSGID":{"type":"b","data":false},"CtrlAltDelBurstAction":{"type":"s","data":"reboot-force"},"SoftRebootsCount":{"type":"u","data":0}}]}}`

func TestReplayIsByteDeterministicAcrossTwoRuns(t *testing.T) {
	dir := stageReplayDir(t, healthyOsRelease, "corpus-host", "8d5a9a1e-6f50-4a12-9c3b-2b1d0e9f7a44\n")
	env := map[string]string{"SE_REPLAY_DIR": dir}

	code1, first, stderr := runWith(t, "collect identity:658\n", env)
	code2, second, _ := runWith(t, "collect identity:658\n", env)
	if code1 != exitOK || code2 != exitOK {
		t.Fatalf("exits %d/%d, stderr: %s", code1, code2, stderr)
	}
	if first != second {
		t.Fatalf("replay is not byte-deterministic:\n%s\nvs\n%s", first, second)
	}
}

func TestReplayPinsEveryRunVaryingMember(t *testing.T) {
	dir := stageReplayDir(t, healthyOsRelease, "corpus-host", "8d5a9a1e-6f50-4a12-9c3b-2b1d0e9f7a44\n")
	code, stdout, stderr := runWith(t, "collect identity:658\n", map[string]string{"SE_REPLAY_DIR": dir})
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	records := parseRecords(t, stdout)

	begin := ofKind(records, "begin")[0]
	if begin["request"] != "replay" || begin["batch"] != "replay" {
		t.Errorf("replay pins batch and request to the constant \"replay\"; got %v/%v", begin["request"], begin["batch"])
	}
	if begin["boot_id"] != "8d5a9a1e-6f50-4a12-9c3b-2b1d0e9f7a44" {
		t.Errorf("boot_id must be the staged file, trimmed; got %v", begin["boot_id"])
	}
	if begin["timens"] != 0.0 {
		t.Errorf("no time namespace was observed at capture, so timens is 0; got %v", begin["timens"])
	}
	if begin["instance"] != nil {
		t.Errorf("host-native means instance null, and only null; got %v", begin["instance"])
	}
	// The declaration hash stays REAL under replay — the bytes it covers
	// are static, so determinism costs nothing and the collator's
	// refetch-on-mismatch contract keeps meaning something.
	declaration, _ := begin["declaration"].(string)
	if declaration != declarationDigest || !strings.HasPrefix(declaration, "sha256:") || len(declaration) != len("sha256:")+64 {
		t.Errorf("begin.declaration %q must be the sha256 of the exact declare bytes", declaration)
	}

	if at := ofKind(records, "object")[0]["at"]; at != 1.0 {
		t.Errorf("the first replayed object carries at = 1.0 + 0.001*0; got %v", at)
	}
	end := ofKind(records, "end")[0]
	if end["cpu_ms"] != 0.5 || end["wall_ms"] != 1.0 {
		t.Errorf("replay pins cpu_ms=0.5 wall_ms=1.0; got %v/%v", end["cpu_ms"], end["wall_ms"])
	}
}

func TestReplayBootIDFallsBackToTheFixedID(t *testing.T) {
	dir := stageReplayDir(t, healthyOsRelease, "corpus-host", "")
	_, stdout, _ := runWith(t, "collect identity:1\n", map[string]string{"SE_REPLAY_DIR": dir})
	begin := ofKind(parseRecords(t, stdout), "begin")[0]
	if begin["boot_id"] != replayBootID {
		t.Fatalf("a variant staging no boot_id gets the fixed v4-shaped id %s; got %v", replayBootID, begin["boot_id"])
	}
}

func TestReplayNowIsIgnoredButNeverACrash(t *testing.T) {
	// This collector derives nothing from wall time, so SE_REPLAY_NOW has
	// nothing to pin — the contract is only that setting it changes
	// nothing and breaks nothing.
	dir := stageReplayDir(t, healthyOsRelease, "corpus-host", "")
	bare := map[string]string{"SE_REPLAY_DIR": dir}
	pinned := map[string]string{"SE_REPLAY_DIR": dir, "SE_REPLAY_NOW": "2026-08-14T12:00:00Z"}

	code1, first, _ := runWith(t, "collect identity:2\n", bare)
	code2, second, _ := runWith(t, "collect identity:2\n", pinned)
	if code1 != exitOK || code2 != exitOK || first != second {
		t.Fatalf("SE_REPLAY_NOW changed the outcome: exits %d/%d", code1, code2)
	}
}

func TestReplayWithoutOsReleaseDeclinesAbsentAndCommitsZero(t *testing.T) {
	dir := stageReplayDir(t, "", "corpus-host", "")
	code, stdout, stderr := runWith(t, "collect identity:77\n", map[string]string{"SE_REPLAY_DIR": dir})
	if code != exitOK {
		t.Fatalf("an honest absence exits zero; got %d, stderr: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	declines := ofKind(records, "decline")
	if len(declines) != 1 || declines[0]["reason"] != "absent" {
		t.Fatalf("expected the absent decline, got %v", declines)
	}
	commits := ofKind(records, "commit")
	if len(commits) != 1 || commits[0]["objects"] != 0.0 || commits[0]["generation"] != 77.0 {
		t.Fatalf("absent commits zero under the issued generation; got %v", commits)
	}
}

func TestReplayWithUnreadableOsReleaseDeclinesUnavailable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads through file modes, so the staged unreadability would not hold")
	}
	dir := stageReplayDir(t, healthyOsRelease, "corpus-host", "")
	if err := os.Chmod(filepath.Join(dir, "os-release"), 0o000); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ := runWith(t, "collect identity:6\n", map[string]string{"SE_REPLAY_DIR": dir})
	if code != exitOK {
		t.Fatalf("a decline is data, never an error exit; got %d", code)
	}
	records := parseRecords(t, stdout)
	declines := ofKind(records, "decline")
	if len(declines) != 1 || declines[0]["reason"] != "unavailable" {
		t.Fatalf("expected the unavailable decline, got %v", declines)
	}
	if len(ofKind(records, "commit")) != 0 {
		t.Fatal("unavailable established nothing and must not commit")
	}
}

func TestReplayWithUncapturedHostnameRefusesToRun(t *testing.T) {
	// os-release staged, hostname not: a broken capture, not a statement
	// about any machine — so "I could not run", never a decline that would
	// lie about the host the payloads came from.
	dir := stageReplayDir(t, healthyOsRelease, "", "")
	code, _, stderr := runWith(t, "collect identity:5\n", map[string]string{"SE_REPLAY_DIR": dir})
	if code != exitRuntime {
		t.Fatalf("exit %d, want %d", code, exitRuntime)
	}
	if !strings.Contains(stderr, "not captured") {
		t.Fatalf("stderr must name the missing capture: %q", stderr)
	}
}

func TestProbeAnswersWithAVerdictNotAnExitCode(t *testing.T) {
	ready := stageReplayDir(t, healthyOsRelease, "corpus-host", "")
	code, stdout, _ := runWith(t, "probe\n", map[string]string{"SE_REPLAY_DIR": ready})
	if code != exitOK || !strings.Contains(stdout, `"verdict":"yes"`) {
		t.Fatalf("exit %d, stdout %q", code, stdout)
	}

	// A no is still exit zero: the verdict is the answer, and a non-zero
	// exit would read as a crash (DESIGN 18).
	bare := stageReplayDir(t, "", "", "")
	code, stdout, _ = runWith(t, "probe\n", map[string]string{"SE_REPLAY_DIR": bare})
	if code != exitOK || !strings.Contains(stdout, `"verdict":"no"`) {
		t.Fatalf("exit %d, stdout %q", code, stdout)
	}
	record := parseRecords(t, stdout)[0]
	if record["reason"] == "" || record["reason"] == nil {
		t.Fatal("a verdict without its why is not actionable")
	}
}
