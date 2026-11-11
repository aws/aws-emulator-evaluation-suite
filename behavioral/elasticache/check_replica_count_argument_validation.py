"""replica-count-argument-validation."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _fault_base(code):
    """Strip the modeled Fault/Exception suffix so error codes compare on their base."""
    for suffix in ("Exception", "Fault"):
        if code and code.endswith(suffix) and len(code) > len(suffix):
            return code[: -len(suffix)]
    return code

def _error(fn):
    """Call fn(); return (code, message) from the ClientError it must raise.

    An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")

def _assert_error(fn, expected):
    """Assert fn() fails with `expected` (Fault/Exception-suffix normalized); return the message."""
    code, message = _error(fn)
    assert _fault_base(code) == _fault_base(expected), f"expected {expected}, got {code}"
    return message

CHECK = "replica-count-argument-validation"
GROUP = 'replication-group'
SERVICES = ['elasticache']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Increase/DecreaseReplicaCount on a nonexistent id fail with InvalidParameterValue "Replication group
    <id> does not exist." (argument validation first), while Describe and ModifyReplicationGroup on the same
    id fail with ReplicationGroupNotFoundFault and their exact messages."""
    ec = ctx.client("elasticache")
    bogus = ctx.unique_name("sim2real-behav-erg-replicas-")
    message = _assert_error(
        lambda: ec.increase_replica_count(
            ReplicationGroupId=bogus, NewReplicaCount=1, ApplyImmediately=True,
        ),
        "InvalidParameterValueException",
    )
    assert message == f"Replication group {bogus} does not exist.", message
    message = _assert_error(
        lambda: ec.decrease_replica_count(
            ReplicationGroupId=bogus, NewReplicaCount=0, ApplyImmediately=True,
        ),
        "InvalidParameterValueException",
    )
    assert message == f"Replication group {bogus} does not exist.", message

    # Differential control: an ordinary lookup-first read and mutation on the
    # SAME nonexistent id must hit ReplicationGroupNotFoundFault, not
    # InvalidParameterValueException -- proving the id genuinely doesn't
    # exist and that the two replica-count ops are the exception, not the
    # service-wide behavior for this id.
    message = _assert_error(
        lambda: ec.describe_replication_groups(ReplicationGroupId=bogus),
        "ReplicationGroupNotFoundFault",
    )
    assert message == f"ReplicationGroup {bogus} not found.", message
    message = _assert_error(
        lambda: ec.modify_replication_group(ReplicationGroupId=bogus, ApplyImmediately=True),
        "ReplicationGroupNotFoundFault",
    )
    assert message == f"Replication group '{bogus}' not found", message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
