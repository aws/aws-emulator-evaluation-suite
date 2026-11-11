"""global-replication-group-topology-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _fault_base(code):
    """Strip the modeled Fault/Exception suffix so error codes compare on their base."""
    for suffix in ("Exception", "Fault"):
        if code and code.endswith(suffix) and len(code) > len(suffix):
            return code[: -len(suffix)]
    return code

def _error(fn, expected):
    """Call fn() and return its ClientError (code, message); raise if the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected {expected} but the call SUCCEEDED")

def _refusal(fn, expected):
    """(code without its modeled Fault/Exception suffix, message) of the error fn() raises."""
    code, message = _error(fn, expected)
    return _fault_base(code), message

_GRG_NOT_FOUND = "Global Replication Group not found"

CHECK = "global-replication-group-topology-not-found"
GROUP = 'global-replication-group'
SERVICES = ['elasticache']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Failover/resharding/rebalance on an unknown global replication group raise GlobalReplicationGroupNotFound."""
    ec = ctx.client("elasticache")
    bogus = ctx.unique_name("sim2real-behav-egrg-topo-")
    refused = _refusal(
        lambda: ec.failover_global_replication_group(
            GlobalReplicationGroupId=bogus,
            PrimaryRegion=ctx.region,
            PrimaryReplicationGroupId=ctx.unique_name("sim2real-behav-erg-x-"),
        ),
        "GlobalReplicationGroupNotFoundFault",
    )
    assert refused == (
        "GlobalReplicationGroupNotFound",
        _GRG_NOT_FOUND,
    ), f"expected GlobalReplicationGroupNotFound with its exact message, got {refused!r}"
    refused = _refusal(
        lambda: ec.increase_node_groups_in_global_replication_group(
            GlobalReplicationGroupId=bogus, NodeGroupCount=2, ApplyImmediately=True,
        ),
        "GlobalReplicationGroupNotFoundFault",
    )
    assert refused == (
        "GlobalReplicationGroupNotFound",
        _GRG_NOT_FOUND,
    ), f"expected GlobalReplicationGroupNotFound with its exact message, got {refused!r}"
    refused = _refusal(
        lambda: ec.decrease_node_groups_in_global_replication_group(
            GlobalReplicationGroupId=bogus,
            NodeGroupCount=1,
            ApplyImmediately=True,
            GlobalNodeGroupsToRemove=["0002"],
        ),
        "GlobalReplicationGroupNotFoundFault",
    )
    assert refused == (
        "GlobalReplicationGroupNotFound",
        _GRG_NOT_FOUND,
    ), f"expected GlobalReplicationGroupNotFound with its exact message, got {refused!r}"
    refused = _refusal(
        lambda: ec.rebalance_slots_in_global_replication_group(
            GlobalReplicationGroupId=bogus, ApplyImmediately=True,
        ),
        "GlobalReplicationGroupNotFoundFault",
    )
    assert refused == (
        "GlobalReplicationGroupNotFound",
        _GRG_NOT_FOUND,
    ), f"expected GlobalReplicationGroupNotFound with its exact message, got {refused!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
