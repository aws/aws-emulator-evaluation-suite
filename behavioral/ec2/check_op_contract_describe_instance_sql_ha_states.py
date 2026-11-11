"""op-contract-describeInstanceSqlHaStates."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeInstanceSqlHaStates"
GROUP = "error-semantics"
SERVICES = ["ec2"]
_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeInstanceSqlHaStates answers with an Instances list; a well-formed unregistered instance ID
    fails with InvalidInstanceID.NotFound without DryRun and answers DryRunOperation with DryRun
    (exact messages)."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_instance_sql_ha_states(
        Filters=[{"Name": "sqlServerLicenseUsage", "Values": ["full"]}]
    )
    assert "Instances" in resp, "response missing 'Instances' list"
    assert isinstance(resp["Instances"], list)
    for item in resp["Instances"]:
        assert "InstanceId" in item and "HaStatus" in item

    bogus_id = "i-1234567890abcdef0"
    code, message = _error(lambda: ec2.describe_instance_sql_ha_states(InstanceIds=[bogus_id]))
    assert code == "InvalidInstanceID.NotFound", f"unexpected error code: {code}"
    expected = (
        f"Requested instance ID(s) [{bogus_id}] not found in account or SQL HA standby "
        "detection not enabled."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    code, message = _error(
        lambda: ec2.describe_instance_sql_ha_states(InstanceIds=[bogus_id], DryRun=True)
    )
    assert code == "DryRunOperation", (
        f"expected the DryRun permission check to precede instance-ID existence, got {code}"
    )
    assert message == _DRY_RUN_MESSAGE, f"expected message {_DRY_RUN_MESSAGE!r}, got {message!r}"

    code, message = _error(lambda: ec2.describe_instance_sql_ha_states(DryRun=True))
    assert code == "DryRunOperation", f"unexpected error code: {code}"
    assert message == _DRY_RUN_MESSAGE, f"expected message {_DRY_RUN_MESSAGE!r}, got {message!r}"


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
