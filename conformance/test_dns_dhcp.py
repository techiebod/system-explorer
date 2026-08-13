"""The kea and unbound pure halves: socket-protocol documents parsed.

Both daemons answer machine formats — Kea JSON, unbound strict key=value
records — and the shapes pinned here are the ones a version drift would
break silently: Kea's [[value, timestamp]] statistic lists, the subnet-id
join to config-get's CIDRs (wherever the subnet is declared, shared
networks included), the subnet-over-network-over-global option
inheritance with never-send suppressions, the lease state names and
expiry arithmetic (with 'never' for the infinite lifetime), the
reservation ids that stay distinct when one address carries several
machines, the hook gate that keeps a missing lease_cmds library from
reading as an outage, and unbound's decimal averages beside its integer
counters.
"""

import asyncio
import os
import shutil
import tempfile

from system_explorer.agent.adapters.kea import (Adapter, config_subnet_facts,
                                                gated_collections, lease_rows,
                                                reservation_rows, subnet_cidrs,
                                                subnet_rows)
from system_explorer.agent.adapters.unbound import parse_stats, parse_status
from system_explorer.agent.rules.kea import subnet_opinions

# A config-get Dhcp4 document in miniature: global lease time and options,
# one subnet overriding routers but not DNS or lifetime, one overriding
# lifetime with no options of its own, one declared inside a shared
# network (network-level lifetime and options between it and the
# globals), and a global reservation. Addresses are RFC 5737, MACs are
# the RFC 7042 documentation range.
DHCP4 = {
    "valid-lifetime": 4000,
    "option-data": [
        {"name": "routers", "data": "192.0.2.1"},
        {"name": "domain-name-servers", "data": "192.0.2.53, 192.0.2.54"},
        {"name": "domain-name", "data": "example.net"},  # not a folded option
    ],
    "subnet4": [
        {"id": 1, "subnet": "192.0.2.0/24",
         "option-data": [{"name": "routers", "data": "192.0.2.254"}],
         "reservations": [
             {"ip-address": "192.0.2.10",
              "hw-address": "00:00:5e:00:53:0a", "hostname": "printer"},
             {"hw-address": "00:00:5e:00:53:0b"},  # no ip-address: no stable id
         ]},
        {"id": 2, "subnet": "198.51.100.0/24", "valid-lifetime": 600},
    ],
    "shared-networks": [
        {"name": "backbone", "valid-lifetime": 1200,
         "option-data": [
             {"name": "routers", "data": "203.0.113.1"},
             {"name": "domain-name-servers", "data": "203.0.113.53"},
         ],
         "subnet4": [
             {"id": 5, "subnet": "203.0.113.0/24",
              "option-data": [{"name": "routers", "data": "203.0.113.254"}],
              "reservations": [
                  {"ip-address": "203.0.113.10",
                   "hw-address": "00:00:5e:00:53:05"},
              ]},
         ]},
    ],
    "reservations": [  # global (reservations-global): subnet-scoped to nothing
        {"ip-address": "192.0.2.40", "hw-address": "00:00:5e:00:53:28",
         "hostname": "doorbell"},
    ],
}


def test_kea_statistics_fold_to_subnet_rows_with_their_config_facts():
    stats = {
        "subnet[1].total-addresses": [[200, "2026-08-13 00:00:00"]],
        "subnet[1].assigned-addresses": [[181, "2026-08-13 00:00:00"]],
        "subnet[1].declined-addresses": [[0, "2026-08-13 00:00:00"]],
        "subnet[2].total-addresses": [[50, "2026-08-13 00:00:00"]],
        "subnet[2].assigned-addresses": [[3, "2026-08-13 00:00:00"]],
        "subnet[3].total-addresses": [[0, "2026-08-13 00:00:00"]],
        "subnet[3].assigned-addresses": [[0, "2026-08-13 00:00:00"]],
        "pkt4-received": [[9999, "2026-08-13 00:00:00"]],  # not a subnet stat
    }
    rows = subnet_rows(stats, config_subnet_facts(DHCP4))
    assert [row["SubnetId"] for row in rows] == [1, 2, 3]
    assert rows[0]["Subnet"] == "192.0.2.0/24"
    assert rows[0]["UsedPercent"] == 90  # round(181 * 100 / 200)
    assert rows[1]["UsedPercent"] == 6
    assert "Subnet" not in rows[2]  # no CIDR known: absent, never invented
    assert "UsedPercent" not in rows[2]  # total 0: no meaningful division
    [opinion] = subnet_opinions(rows[0])
    assert (opinion["key"], opinion["level"]) == ("kea-pool-capacity", "warn")
    assert subnet_opinions(rows[1]) == []


def test_kea_config_facts_fall_back_from_subnet_to_global():
    facts = config_subnet_facts(DHCP4)
    assert facts["1"]["LeaseTimeSeconds"] == 4000  # subnet silent: global
    assert facts["2"]["LeaseTimeSeconds"] == 600  # subnet override wins
    assert facts["1"]["Routers"] == "192.0.2.254"  # subnet override wins
    assert facts["2"]["Routers"] == "192.0.2.1"  # subnet silent: global
    assert facts["1"]["DnsServers"] == "192.0.2.53, 192.0.2.54"  # Kea's own comma string
    # ReservationCount counts what the config states, including the
    # ip-address-less reservation the rows collection cannot mint an id
    # for — and UnlistedReservations states that remainder on the row.
    assert facts["1"]["ReservationCount"] == 2
    assert facts["1"]["UnlistedReservations"] == 1
    assert facts["2"]["ReservationCount"] == 0
    assert "UnlistedReservations" not in facts["2"]  # nothing unlisted: absent
    assert "example.net" not in str(facts)  # only routers and DNS fold


def test_kea_shared_network_subnets_keep_their_config_facts():
    """A subnet declared inside shared-networks is still a subnet:
    losing its CIDR, lifetime, options and reservations while its
    statistics row kept appearing would mask absence as a healthy row."""
    facts = config_subnet_facts(DHCP4)
    assert facts["5"]["Subnet"] == "203.0.113.0/24"
    assert facts["5"]["LeaseTimeSeconds"] == 1200  # network beats global 4000
    assert facts["5"]["Routers"] == "203.0.113.254"  # subnet beats network
    assert facts["5"]["DnsServers"] == "203.0.113.53"  # network beats global
    assert facts["5"]["ReservationCount"] == 1
    assert subnet_cidrs(DHCP4)["5"] == "203.0.113.0/24"


def test_kea_never_send_suppressions_mask_wider_scopes():
    """never-send withholds the option entirely: the row must not state
    a gateway or resolver the client is never handed — a data-less
    subnet suppression must not fall through to the global value, and a
    never-send entry carrying data contributes nothing either."""
    config = {
        "option-data": [
            {"name": "routers", "data": "192.0.2.1"},
            {"name": "domain-name-servers", "data": "192.0.2.53"},
        ],
        "subnet4": [
            # The normalized shape config-get emits: data "" plus the flag.
            {"id": 1, "subnet": "192.0.2.0/24",
             "option-data": [
                 {"name": "routers", "data": "", "never-send": True}]},
            # never-send AND data present: still never sent.
            {"id": 2, "subnet": "198.51.100.0/24",
             "option-data": [
                 {"name": "domain-name-servers", "data": "198.51.100.53",
                  "never-send": True}]},
        ],
    }
    facts = config_subnet_facts(config)
    assert "Routers" not in facts["1"]  # suppression masks the global value
    assert facts["1"]["DnsServers"] == "192.0.2.53"  # sibling untouched
    assert "DnsServers" not in facts["2"]  # the flag beats the entry's own data
    assert facts["2"]["Routers"] == "192.0.2.1"


def test_kea_reservations_fold_to_rows_with_stable_ids():
    rows = reservation_rows(DHCP4)
    assert rows == [
        ("reservation:1/192.0.2.10",
         {"IpAddress": "192.0.2.10", "HwAddress": "00:00:5e:00:53:0a",
          "Hostname": "printer", "Subnet": "192.0.2.0/24"}),
        ("reservation:5/203.0.113.10",  # declared inside a shared network
         {"IpAddress": "203.0.113.10", "HwAddress": "00:00:5e:00:53:05",
          "Subnet": "203.0.113.0/24"}),
        ("reservation:global/192.0.2.40",  # global: no Subnet, none invented
         {"IpAddress": "192.0.2.40", "HwAddress": "00:00:5e:00:53:28",
          "Hostname": "doorbell"}),
    ]


def test_kea_duplicate_ip_reservations_keep_distinct_reachable_ids():
    """ip-reservations-unique: false lets one address carry several
    machines; one id for several rows would leave every row after the
    first unreachable by id. Unique ids never churn; colliding ones
    gain the hw-address, or an ordinal when even that cannot tell the
    rows apart."""
    config = {"subnet4": [
        {"id": 1, "subnet": "192.0.2.0/24", "reservations": [
            {"ip-address": "192.0.2.10", "hw-address": "00:00:5e:00:53:0a"},
            {"ip-address": "192.0.2.10", "hw-address": "00:00:5e:00:53:0b"},
            {"ip-address": "192.0.2.11", "hw-address": "00:00:5e:00:53:0c"},
            {"ip-address": "192.0.2.12"},  # colliding below, and no hw-address
            {"ip-address": "192.0.2.12"},
        ]}]}
    ids = [row_id for row_id, _ in reservation_rows(config)]
    assert ids == [
        "reservation:1/192.0.2.10/00:00:5e:00:53:0a",
        "reservation:1/192.0.2.10/00:00:5e:00:53:0b",
        "reservation:1/192.0.2.11",  # unique: exactly as minted, no churn
        "reservation:1/192.0.2.12/#1",
        "reservation:1/192.0.2.12/#2",
    ]
    assert len(set(ids)) == len(ids)


def test_kea_leases_fold_with_state_names_and_expiry():
    leases = [
        {"ip-address": "192.0.2.20", "hw-address": "00:00:5e:00:53:14",
         "hostname": "laptop", "state": 0, "subnet-id": 1,
         "cltt": 1700000000, "valid-lft": 600},
        {"ip-address": "192.0.2.21", "state": 1, "subnet-id": 9,
         "valid-lft": 600},  # no cltt: no expiry arithmetic
        {"ip-address": "192.0.2.22", "state": 2, "subnet-id": 1},
        {"ip-address": "203.0.113.20", "state": 0, "subnet-id": 5,
         "cltt": 1700000000, "valid-lft": 4294967295},  # infinite lifetime
        {"state": 0},  # no ip-address: no stable lease:<ip> id
    ]
    rows = lease_rows(leases, subnet_cidrs(DHCP4))
    assert [row["IpAddress"] for row in rows] == [
        "192.0.2.20", "192.0.2.21", "192.0.2.22", "203.0.113.20"]
    assert rows[0]["State"] == "default"
    assert rows[0]["Subnet"] == "192.0.2.0/24"
    assert rows[0]["ExpiresAt"] == "2023-11-14T22:23:20Z"  # cltt + valid-lft
    assert rows[1]["State"] == "declined"
    assert "Subnet" not in rows[1]  # subnet-id 9 unknown: absent, not invented
    assert "ExpiresAt" not in rows[1]
    assert rows[2]["State"] == "expired-reclaimed"
    # A shared-network subnet-id still joins to its CIDR, and DHCP's
    # infinite lifetime (0xFFFFFFFF) states 'never', not a year-2162 date.
    assert rows[3]["Subnet"] == "203.0.113.0/24"
    assert rows[3]["ExpiresAt"] == "never"


def test_kea_reservations_source_states_the_unlistable_remainder():
    """Rule 7: a hostname- or class-only reservation cannot be listed,
    and the collection says so on the wire instead of letting its total
    quietly disagree with ReservationCount."""
    adapter = Adapter.__new__(Adapter)
    [note] = adapter._source("reservations")["notes"]
    assert "ip-address" in note
    assert "ReservationCount" in note
    assert "UnlistedReservations" in note
    assert "notes" not in adapter._source("subnets")  # only reservations skip


def test_kea_capability_names_the_socket_when_the_answer_is_unclean():
    """A listener that accepts and closes without answering (Kea
    restarting under a config reload) must decline with the socket path
    and the failure class in the reason, not escape capability() to the
    blanket discovery handler."""
    # AF_UNIX paths are length-capped (~104 bytes on Darwin), so the
    # socket lives under a short mkdtemp rather than pytest's deep
    # tmp_path.
    workdir = tempfile.mkdtemp()
    socket_path = os.path.join(workdir, "kea.sock")

    async def scenario():
        async def close_without_answering(reader, writer):
            await reader.read()  # the command arrives, then no answer
            writer.close()
            await writer.wait_closed()
        server = await asyncio.start_unix_server(close_without_answering,
                                                 path=socket_path)
        try:
            adapter = Adapter.__new__(Adapter)
            adapter.socket_path = socket_path
            return await adapter.capability()
        finally:
            server.close()
            await server.wait_closed()

    try:
        result = asyncio.run(scenario())
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    assert result["available"] is False
    assert socket_path in result["reason"]
    assert "JSONDecodeError" in result["reason"]


def test_kea_leases_gate_on_the_lease_cmds_hook():
    assert gated_collections(["list-commands", "config-get",
                              "lease4-get-all"]) == {}
    gate = gated_collections(["list-commands", "config-get"])
    assert set(gate) == {"leases"}  # every other collection stays up
    assert "libdhcp_lease_cmds" in gate["leases"]
    assert "lease4-get-all" in gate["leases"]


def test_unbound_status_and_stats_parse_their_own_formats():
    status = parse_status("version: 1.20.0\nverbosity: 1\nuptime: 86400 seconds\n"
                          "threads: 4\nmodules: 2 [ validator iterator ]\n")
    assert status == {"Version": "1.20.0", "Uptime": 86400}
    stats = parse_stats("total.num.queries=123456\n"
                        "total.num.cachehits=100000\n"
                        "total.num.cachemiss=23456\n"
                        "total.recursion.time.avg=0.084321\n"
                        "histogram.000000.000000.to.000000.000001=0\n")
    assert stats["NumQueries"] == 123456
    assert stats["RecursionTimeAvgSeconds"] == 0.084321
    assert "histogram" not in str(stats)
