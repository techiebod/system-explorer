// The time collection's three shapes, each against real busctl bytes: a
// synchronised host with timesyncd answering, a host whose syncer is not
// timesyncd (four facts unobservable, the collection still committed), and
// a host with no systemd time services at all (the absent decline that
// commits zero). The documents are captures from the lab guests, trimmed
// not at all — the parse must survive every property it does not read.
package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// A debian 13 guest's timedate1 GetAll, 2026-08-21.
const timedateDoc = `{"type":"a{sv}","data":[{"Timezone":{"type":"s","data":"Etc/UTC"},"LocalRTC":{"type":"b","data":false},"CanNTP":{"type":"b","data":true},"NTP":{"type":"b","data":true},"NTPSynchronized":{"type":"b","data":true},"TimeUSec":{"type":"t","data":1787323083006093},"RTCTimeUSec":{"type":"t","data":1787323083000000}}]}`

// The same guest's timesync1 GetAll — every property the interface serves,
// including the tuple-typed ones this collector must skip over unharmed.
const timesyncDoc = `{"type":"a{sv}","data":[{"LinkNTPServers":{"type":"as","data":[]},"SystemNTPServers":{"type":"as","data":[]},"RuntimeNTPServers":{"type":"as","data":[]},"FallbackNTPServers":{"type":"as","data":["0.debian.pool.ntp.org","1.debian.pool.ntp.org","2.debian.pool.ntp.org","3.debian.pool.ntp.org"]},"ServerName":{"type":"s","data":"2.debian.pool.ntp.org"},"ServerAddress":{"type":"(iay)","data":[2,[145,40,176,243]]},"RootDistanceMaxUSec":{"type":"t","data":5000000},"PollIntervalMinUSec":{"type":"t","data":32000000},"PollIntervalMaxUSec":{"type":"t","data":2048000000},"PollIntervalUSec":{"type":"t","data":256000000},"NTPMessage":{"type":"(uuuuittayttttbtt)","data":[0,4,4,1,-25,0,0,[71,80,83,0],1787323275100216,1787323275104113,1787323275104118,1787323275107131,false,4,355]},"Frequency":{"type":"x","data":87127}}]}`

func timeRecords(t *testing.T, src *fakeSource) []map[string]any {
	t.Helper()
	var out, errs bytes.Buffer
	code := collect(&out, &errs, src, []string{"time"}, map[string]uint64{"time": 7})
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errs.String())
	}
	var records []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		records = append(records, record)
	}
	return records
}

func recordOf(records []map[string]any, kind string) map[string]any {
	for _, record := range records {
		if record["record"] == kind {
			return record
		}
	}
	return nil
}

func TestTimeServesTheSynchronisedHost(t *testing.T) {
	src := &fakeSource{host: "guest-1",
		timedate: []byte(timedateDoc), timesync: []byte(timesyncDoc)}
	records := timeRecords(t, src)

	object := recordOf(records, "object")
	if object == nil || object["type"] != "time" || object["name"] != "guest-1" {
		t.Fatalf("%+v", object)
	}
	facts := object["facts"].(map[string]any)
	if facts["Timezone"] != "Etc/UTC" || facts["NTP"] != true ||
		facts["NTPSynchronized"] != true || facts["LocalRTC"] != false {
		t.Fatalf("%+v", facts)
	}
	// Seconds precision, UTC, exactly the reference's rendering of TimeUSec.
	if facts["CurrentTime"] != "2026-08-21T14:38:03Z" {
		t.Fatalf("CurrentTime: %v", facts["CurrentTime"])
	}
	if facts["CurrentNTPServer"] != "2.debian.pool.ntp.org" {
		t.Fatalf("%+v", facts)
	}
	// 32000000 and 2048000000 microseconds: 32 and 2048 whole seconds.
	if poll, _ := json.Marshal(facts["PollIntervalSeconds"]); string(poll) != "[32,2048]" {
		t.Fatalf("PollIntervalSeconds: %s", poll)
	}
	// SystemNTPServers is empty on this host and STILL a fact: an empty
	// configured list is a reading, not an absence.
	if servers, _ := json.Marshal(facts["SystemNTPServers"]); string(servers) != "[]" {
		t.Fatalf("SystemNTPServers: %s", servers)
	}
	commit := recordOf(records, "commit")
	if commit["objects"] != float64(1) || commit["unobservable"] != float64(0) {
		t.Fatalf("%+v", commit)
	}
	if recordOf(records, "unobservable") != nil {
		t.Fatal("nothing was unobservable on this host")
	}
}

func TestTimesyncDarkMakesExactlyItsFourFactsUnobservable(t *testing.T) {
	// The chrony shape: timedate1 answers — the clock IS synchronised and
	// this collector can still say so — while timesync1 has nobody behind
	// it. Four unobservable records, one per fact, and the collection
	// commits: a dark enrichment must not cost the host its clock facts.
	src := &fakeSource{host: "guest-2",
		timedate: []byte(timedateDoc), tserr: errCallFailed}
	records := timeRecords(t, src)

	facts := recordOf(records, "object")["facts"].(map[string]any)
	if _, present := facts["CurrentNTPServer"]; present {
		t.Fatalf("an unread fact must not appear as a value: %+v", facts)
	}
	var named []string
	for _, record := range records {
		if record["record"] == "unobservable" {
			if record["reason"] != "unavailable" || record["detail"] != timesyncDark {
				t.Fatalf("%+v", record)
			}
			named = append(named, record["fact"].(string))
		}
	}
	if len(named) != len(timesyncFacts) {
		t.Fatalf("exactly the timesync facts go dark together: %v", named)
	}
	commit := recordOf(records, "commit")
	if commit["objects"] != float64(1) || commit["unobservable"] != float64(4) {
		t.Fatalf("%+v", commit)
	}
}

func TestNoSystemdTimeServicesIsTheAbsentDeclineThatCommits(t *testing.T) {
	src := &fakeSource{host: "guest-3", tderr: errNoSystemd}
	records := timeRecords(t, src)
	decline := recordOf(records, "decline")
	if decline["reason"] != "absent" {
		t.Fatalf("%+v", decline)
	}
	commit := recordOf(records, "commit")
	if commit == nil || commit["objects"] != float64(0) {
		t.Fatalf("absent must commit zero, so a host rebuilt without systemd "+
			"retires its old clock facts: %+v", commit)
	}
}

func TestTimedate1SilentDeclinesWithoutCommitting(t *testing.T) {
	src := &fakeSource{host: "guest-4", tderr: errCallFailed}
	records := timeRecords(t, src)
	decline := recordOf(records, "decline")
	if decline["reason"] != "unavailable" {
		t.Fatalf("%+v", decline)
	}
	if recordOf(records, "commit") != nil {
		t.Fatal("unavailable establishes nothing and must not commit")
	}
}
