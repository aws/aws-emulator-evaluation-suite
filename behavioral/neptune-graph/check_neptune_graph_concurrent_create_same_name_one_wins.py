"""neptune-graph-concurrent-create-same-name-one-wins."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "neptune-graph-concurrent-create-same-name-one-wins"
GROUP = "concurrency"
SERVICES = ["neptune-graph"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Racing CreateGraph calls for one graphName: exactly one succeeds, every other gets ConflictException
    with the exact message, and the winner reaches AVAILABLE under that name."""
    ng = ctx.client("neptune-graph")
    name = ctx.unique_name("sim2real-ng-race-")
    racer_count = 5

    def _racer(_i):
        try:
            resp = ng.create_graph(
                graphName=name,
                provisionedMemory=16,
                deletionProtection=False,
                publicConnectivity=False,
                tags={"sim2real": CHECK},
            )
            return ("ok", resp["id"])
        except ClientError as e:
            return ("error", (e.response["Error"]["Code"], e.response["Error"]["Message"]))

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        outcomes = list(pool.map(_racer, range(racer_count)))

    winners = [gid for kind, gid in outcomes if kind == "ok"]
    losers = [code for kind, code in outcomes if kind == "error"]

    assert len(winners) == 1, f"expected exactly one winner, got {winners}"
    assert len(losers) == racer_count - 1, f"expected {racer_count - 1} losers, got {losers}"
    assert all(code == "ConflictException" for code, _ in losers), losers
    exists = f"Graph with name {name} already exists!"
    assert all(message == exists for _, message in losers), losers

    graph_id = winners[0]
    ctx.on_cleanup(lambda: _force_delete_graph(ng, graph_id))

    final = _poll_until(
        lambda: ng.get_graph(graphIdentifier=graph_id),
        lambda g: g["status"] in ("AVAILABLE", "FAILED"),
        timeout_s=900,
        interval_s=15,
    )
    assert final["status"] == "AVAILABLE", final["status"]
    assert final["name"] == name, f"expected winning graph name {name!r}, got {final['name']!r}"


# ===== helpers =====
def _poll_until(probe, predicate, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _force_delete_graph(ng, graph_id):
    def _settle(timeout_s):
        return _poll_until(
            lambda: ng.get_graph(graphIdentifier=graph_id),
            lambda g: g["status"] in ("AVAILABLE", "FAILED", "STOPPED"),
            timeout_s=timeout_s,
            interval_s=2,
        )

    try:
        if _settle(900).get("deletionProtection"):
            ng.update_graph(graphIdentifier=graph_id, deletionProtection=False)
            _settle(120)
        ng.delete_graph(graphIdentifier=graph_id, skipSnapshot=True)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
