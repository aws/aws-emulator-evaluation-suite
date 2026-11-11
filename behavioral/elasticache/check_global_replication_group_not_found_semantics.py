"""global-replication-group-not-found-semantics."""
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

CHECK = "global-replication-group-not-found-semantics"
GROUP = 'global-replication-group'
SERVICES = ['elasticache']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Global-replication-group reads/mutations on an unknown id raise GlobalReplicationGroupNotFound."""
    ec = ctx.client("elasticache")
    bogus = ctx.unique_name("sim2real-behav-egrg-")
    refused = _refusal(
        lambda: ec.describe_global_replication_groups(
            GlobalReplicationGroupId=bogus, ShowMemberInfo=True,
        ),
        "GlobalReplicationGroupNotFoundFault",
    )
    assert refused == (
        "GlobalReplicationGroupNotFound",
        _GRG_NOT_FOUND,
    ), f"expected GlobalReplicationGroupNotFound with its exact message, got {refused!r}"
    refused = _refusal(
        lambda: ec.delete_global_replication_group(
            GlobalReplicationGroupId=bogus, RetainPrimaryReplicationGroup=True,
        ),
        "GlobalReplicationGroupNotFoundFault",
    )
    assert refused == (
        "GlobalReplicationGroupNotFound",
        _GRG_NOT_FOUND,
    ), f"expected GlobalReplicationGroupNotFound with its exact message, got {refused!r}"
    refused = _refusal(
        lambda: ec.modify_global_replication_group(
            GlobalReplicationGroupId=bogus,
            ApplyImmediately=True,
            GlobalReplicationGroupDescription="nope",
        ),
        "GlobalReplicationGroupNotFoundFault",
    )
    assert refused == (
        "GlobalReplicationGroupNotFound",
        _GRG_NOT_FOUND,
    ), f"expected GlobalReplicationGroupNotFound with its exact message, got {refused!r}"
    refused = _refusal(
        lambda: ec.disassociate_global_replication_group(
            GlobalReplicationGroupId=bogus,
            ReplicationGroupId=ctx.unique_name("sim2real-behav-erg-x-"),
            ReplicationGroupRegion=ctx.region,
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
