"""outbound-cross-cluster-connection-to-nonexistent-domains-validates-asynchronously."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "outbound-cross-cluster-connection-to-nonexistent-domains-validates-asynchronously"
GROUP = 'cross-cluster-search'
SERVICES = ['es']


def _poll_terminal(fn, *, budget_s: float = 240.0, poll_s: float = 5.0):
    """The first non-VALIDATING ConnectionStatus ``fn()`` observes, within ``budget_s``."""
    deadline = time.monotonic() + budget_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if last["StatusCode"] != "VALIDATING":
            return last
        time.sleep(poll_s)
    raise AssertionError(f"connection never left VALIDATING within {budget_s}s; last={last!r}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateOutboundCrossClusterSearchConnection accepts a source/destination pair naming
    domains that were never created, answering 200 VALIDATING at once, then the connection
    settles to VALIDATION_FAILED once AWS checks the domains asynchronously.
    """
    es = ctx.client("es")
    source_name = ctx.unique_name("sim2real-ccs-")[:28].rstrip("-")
    dest_name = ctx.unique_name("sim2real-ccs-")[:28].rstrip("-")
    alias = ctx.unique_name("sim2real-")[:20]

    created = es.create_outbound_cross_cluster_search_connection(
        SourceDomainInfo={"OwnerId": ctx.account, "DomainName": source_name, "Region": ctx.region},
        DestinationDomainInfo={"OwnerId": ctx.account, "DomainName": dest_name, "Region": ctx.region},
        ConnectionAlias=alias,
    )
    conn_id = created["CrossClusterSearchConnectionId"]
    ctx.on_cleanup(lambda: es.delete_outbound_cross_cluster_search_connection(
        CrossClusterSearchConnectionId=conn_id))
    assert created["ConnectionStatus"]["StatusCode"] == "VALIDATING", (
        f"the initial create answer should be VALIDATING, got "
        f"{created['ConnectionStatus']['StatusCode']!r}"
    )

    def _describe():
        rows = es.describe_outbound_cross_cluster_search_connections(
            Filters=[{"Name": "cross-cluster-search-connection-id", "Values": [conn_id]}]
        )["CrossClusterSearchConnections"]
        assert len(rows) == 1, f"expected exactly one connection row for {conn_id}, got {rows!r}"
        return rows[0]["ConnectionStatus"]

    terminal = _poll_terminal(_describe)
    assert terminal["StatusCode"] == "VALIDATION_FAILED", (
        f"a connection naming domains that do not exist should settle to VALIDATION_FAILED, "
        f"got {terminal!r}"
    )
    assert terminal.get("Message"), "VALIDATION_FAILED should carry a non-empty Message"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
