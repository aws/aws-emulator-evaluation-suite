"""neptune-graph-delete-graph-deletion-protection-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "neptune-graph-delete-graph-deletion-protection-rejected"
GROUP = "overly-permissive"
SERVICES = ["neptune-graph"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteGraph on a graph with deletionProtection fails with ValidationException and the exact message
    and leaves it AVAILABLE and protected; with protection off, the graph is deleted and GetGraph fails
    with ResourceNotFoundException and the exact message."""
    ng = ctx.client("neptune-graph")
    graph_id = _create_available_graph(ctx, ng, deletion_protection=True)

    code, msg = _error(lambda: ng.delete_graph(graphIdentifier=graph_id, skipSnapshot=True))
    assert code == "ValidationException", code
    expected = f"Graph [{graph_id}] cannot be deleted because deletion protection is enabled."
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    # Effect absent: the graph must still exist, unaffected, with protection still on.
    still_there = ng.get_graph(graphIdentifier=graph_id)
    assert still_there["status"] == "AVAILABLE", f"status={still_there['status']!r}"
    assert still_there["deletionProtection"] is True, (
        f"deletionProtection={still_there['deletionProtection']!r}"
    )

    # Positive control: disabling protection allows the delete to go through.
    ng.update_graph(graphIdentifier=graph_id, deletionProtection=False)
    _poll_until(
        lambda: ng.get_graph(graphIdentifier=graph_id)["status"],
        lambda s: s == "AVAILABLE",
        timeout_s=300,
        interval_s=10,
    )
    ng.delete_graph(graphIdentifier=graph_id, skipSnapshot=True)
    gone_code, gone_msg = _poll_until(
        lambda: _error(lambda: ng.get_graph(graphIdentifier=graph_id), poll=True),
        lambda r: r[0] == "ResourceNotFoundException",
        timeout_s=300,
        interval_s=10,
    )
    assert gone_code == "ResourceNotFoundException", f"CODE={gone_code!r}"
    expected_gone = f"No graph found for customer [{ctx.account}] with graph id [{graph_id}]"
    assert gone_msg == expected_gone, f"expected message {expected_gone!r}, got {gone_msg!r}"


# ===== helpers =====
def _error(fn, *, poll=False):
    """Return the (code, message) of the ClientError fn() raises. A success raises AssertionError;
    with poll=True it returns a sentinel no error code can equal, so a poll keeps waiting."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    if poll:
        return "<call succeeded>", None
    raise AssertionError(f"expected the call to fail, but it succeeded and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_available_graph(ctx, ng, memory=16, deletion_protection=False):
    name = ctx.unique_name("sim2real-ng-")
    graph_id = ng.create_graph(
        graphName=name,
        provisionedMemory=memory,
        deletionProtection=deletion_protection,
        publicConnectivity=False,
        tags={"sim2real": CHECK},
    )["id"]

    def _cleanup():
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

    ctx.on_cleanup(_cleanup)
    status = _poll_until(
        lambda: ng.get_graph(graphIdentifier=graph_id)["status"],
        lambda s: s in ("AVAILABLE", "FAILED"),
        timeout_s=900,
        interval_s=15,
    )
    if status != "AVAILABLE":
        raise AssertionError(f"graph {graph_id} did not reach AVAILABLE, got {status}")
    return graph_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
