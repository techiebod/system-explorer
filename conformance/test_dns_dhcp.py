"""The kea and unbound pure halves: socket-protocol documents parsed.

Both daemons answer machine formats — Kea JSON, unbound strict key=value
records — and the shapes pinned here are the ones a version drift would
break silently: Kea's [[value, timestamp]] statistic lists, the subnet-id
join to config-get's CIDRs, and unbound's decimal averages beside its
integer counters.
"""

from system_explorer.agent.adapters.kea import subnet_rows
from system_explorer.agent.adapters.unbound import parse_stats, parse_status
from system_explorer.agent.rules.kea import subnet_opinions


def test_kea_statistics_fold_to_subnet_rows_with_their_cidrs():
    stats = {
        "subnet[1].total-addresses": [[200, "2026-08-13 00:00:00"]],
        "subnet[1].assigned-addresses": [[181, "2026-08-13 00:00:00"]],
        "subnet[1].declined-addresses": [[0, "2026-08-13 00:00:00"]],
        "subnet[2].total-addresses": [[50, "2026-08-13 00:00:00"]],
        "subnet[2].assigned-addresses": [[3, "2026-08-13 00:00:00"]],
        "pkt4-received": [[9999, "2026-08-13 00:00:00"]],  # not a subnet stat
    }
    rows = subnet_rows(stats, {"1": "192.0.2.0/24"})
    assert [row["SubnetId"] for row in rows] == [1, 2]
    assert rows[0]["Subnet"] == "192.0.2.0/24"
    assert "Subnet" not in rows[1]  # no CIDR known: absent, never invented
    [opinion] = subnet_opinions(rows[0])
    assert (opinion["key"], opinion["level"]) == ("kea-pool-capacity", "warn")
    assert subnet_opinions(rows[1]) == []


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
