"""neptune-graph-delete-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "neptune-graph-delete-lifecycle"
GROUP = "lifecycle"
SERVICES = ["neptune-graph"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Right after DeleteGraph, GetGraph reports DELETING or fails with ResourceNotFoundException; GetGraph
    then settles on ResourceNotFoundException and UpdateGraph fails with it too, each with the exact message."""
    ng = ctx.client("neptune-graph")
    graph_id = _create_available_graph(ctx, ng)

    ng.delete_graph(graphIdentifier=graph_id, skipSnapshot=True)
    expected_gone = f"No graph found for customer [{ctx.account}] with graph id [{graph_id}]"

    try:
        immediate = ng.get_graph(graphIdentifier=graph_id)
        assert immediate["status"] == "DELETING", (
            f"expected status DELETING immediately after DeleteGraph, got {immediate['status']!r}"
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", (
            f"expected DELETING or ResourceNotFoundException immediately after DeleteGraph, got {code!r}"
        )
        msg = e.response["Error"].get("Message")
        assert msg == expected_gone, f"expected message {expected_gone!r}, got {msg!r}"

    final_code, final_msg = _poll_until(
        lambda: _error(lambda: ng.get_graph(graphIdentifier=graph_id), poll=True),
        lambda r: r[0] == "ResourceNotFoundException",
        timeout_s=600,
        interval_s=10,
    )
    assert final_code == "ResourceNotFoundException", (
        f"expected GetGraph on deleted graph {graph_id} to raise ResourceNotFoundException, got {final_code!r}"
    )
    assert final_msg == expected_gone, f"expected message {expected_gone!r}, got {final_msg!r}"

    mutate_code, mutate_msg = _error(lambda: ng.update_graph(graphIdentifier=graph_id, deletionProtection=False))
    assert mutate_code == "ResourceNotFoundException", (
        f"expected UpdateGraph on deleted graph {graph_id} to raise ResourceNotFoundException, got {mutate_code!r}"
    )
    assert mutate_msg == expected_gone, f"expected message {expected_gone!r}, got {mutate_msg!r}"


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
        tags={"sim2real-created-by": "check_graph_delete_lifecycle"},
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
