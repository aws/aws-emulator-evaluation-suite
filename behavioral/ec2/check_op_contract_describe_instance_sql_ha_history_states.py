"""op-contract-describeInstanceSqlHaHistoryStates."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeInstanceSqlHaHistoryStates"
GROUP = "error-semantics"
SERVICES = ["ec2"]
_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeInstanceSqlHaHistoryStates succeeds with an empty/filtered result set
    when no SQL Server HA instances are registered, and honors DryRun."""
    ec2 = ctx.client("ec2")

    # Success path: a scoped, valid call returns the documented shape without error,
    # even though this account almost certainly has no SQL Server HA instances.
    resp = ec2.describe_instance_sql_ha_history_states(
        Filters=[{"Name": "haStatus", "Values": ["active"]}]
    )
    assert "Instances" in resp, "response missing 'Instances' list"
    assert isinstance(resp["Instances"], list), f"expected a list, got {type(resp['Instances'])}"
    for item in resp["Instances"]:
        assert "InstanceId" in item, f"history entry missing 'InstanceId': {item!r}"

    # Error boundary: DryRun short-circuits with DryRunOperation before any other work.
    code, message = _error(lambda: ec2.describe_instance_sql_ha_history_states(DryRun=True))
    assert code == "DryRunOperation", f"unexpected error code: {code}"
    assert message == _DRY_RUN_MESSAGE, f"expected message {_DRY_RUN_MESSAGE!r}, got {message!r}"

    # Negative class: a well-formed but nonexistent instance ID is rejected by identity,
    # not silently filtered to an empty result. Unlike the sibling
    # Enable/DisableInstanceSqlHaStandbyDetections contract (which rejects the same fake ID
    # as InvalidInstanceID.Malformed), this read-side operation validates existence rather
    # than format for the same well-formed-but-fake ID.
    bogus_id = "i-1234567890abcdef0"
    code, message = _error(
        lambda: ec2.describe_instance_sql_ha_history_states(InstanceIds=[bogus_id])
    )
    assert code == "InvalidInstanceID.NotFound", (
        f"expected InvalidInstanceID.NotFound for a nonexistent instance id, got {code}"
    )
    expected = (
        f"Requested instance ID(s) [{bogus_id}] not found in account or SQL HA standby "
        "detection not enabled."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Return fn()'s (code, message); a success raises, never reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
