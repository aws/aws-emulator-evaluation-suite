"""op-contract-disable-instance-sql-ha-standby-detections."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-disable-instance-sql-ha-standby-detections"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DisableInstanceSqlHaStandbyDetections with an unknown instance ID fails with
    InvalidInstanceID.Malformed and the exact message naming the ID, with and without DryRun."""
    ec2 = ctx.client("ec2")
    bogus_id = "i-1234567890abcdef0"

    expected_message = f"The instance ID '{bogus_id}' is malformed"
    code, message = _error(lambda: ec2.disable_instance_sql_ha_standby_detections(
        InstanceIds=[bogus_id], DryRun=True
    ))
    assert code == "InvalidInstanceID.Malformed", (
        f"expected InvalidInstanceID.Malformed even under DryRun, got {code}"
    )
    assert message == expected_message, message

    code, message = _error(lambda: ec2.disable_instance_sql_ha_standby_detections(
        InstanceIds=[bogus_id]
    ))
    assert code == "InvalidInstanceID.Malformed", f"expected InvalidInstanceID.Malformed, got {code}"
    assert message == expected_message, message


def _error(fn):
    """Call fn(); return its error code and message. An unexpected SUCCESS raises, because a
    target ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
