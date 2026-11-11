"""neptune-graph-get-graph-nonexistent-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "neptune-graph-get-graph-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["neptune-graph"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetGraph on a well-formed nonexistent graphIdentifier fails with ResourceNotFoundException and the
    exact message, while GetGraph on a just-created graph returns its id and name."""
    ng = ctx.client("neptune-graph")
    name = ctx.unique_name("sim2real-ng-")
    graph_id = ng.create_graph(
        graphName=name,
        provisionedMemory=16,
        deletionProtection=False,
        publicConnectivity=False,
        tags={"sim2real-check": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: _cleanup_graph(ng, graph_id))

    real = ng.get_graph(graphIdentifier=graph_id)
    assert real["id"] == graph_id, f"expected id {graph_id!r}, got {real.get('id')!r}"
    assert real["name"] == name, f"expected name {name!r}, got {real.get('name')!r}"

    bogus_id = "g-0000000000"
    code, msg = _error(lambda: ng.get_graph(graphIdentifier=bogus_id))
    assert code == "ResourceNotFoundException", (
        f"GetGraph on nonexistent {bogus_id!r} returned {code!r}, expected ResourceNotFoundException"
    )
    expected = f"No graph found for customer [{ctx.account}] with graph id [{bogus_id}]"
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"


# ===== helpers =====
def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected GetGraph on a nonexistent graph to fail, but it returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")
        time.sleep(interval_s)


def _cleanup_graph(ng, graph_id):
    def _settle(timeout_s):
        return _poll_until(
            lambda: ng.get_graph(graphIdentifier=graph_id),
            lambda g: g["status"] not in ("CREATING", "UPDATING"),
            timeout_s=timeout_s,
            interval_s=2,
        )

    try:
        if _settle(1200).get("deletionProtection"):
            ng.update_graph(graphIdentifier=graph_id, deletionProtection=False)
            _settle(120)
        ng.delete_graph(graphIdentifier=graph_id, skipSnapshot=True)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
