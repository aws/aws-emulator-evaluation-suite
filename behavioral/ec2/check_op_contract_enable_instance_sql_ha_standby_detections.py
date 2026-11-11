"""op-contract-enableInstanceSqlHaStandbyDetections."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "op-contract-enableInstanceSqlHaStandbyDetections"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """EnableInstanceSqlHaStandbyDetections with an all-zero instance ID fails with
    InvalidInstanceID.Malformed and its exact message, with and without DryRun."""
    ec2 = ctx.client("ec2")
    fake_instance_id = "i-00000000000000000"
    instance_kwargs = _instance_id_kwargs(ec2, fake_instance_id)

    dry_run_code, dry_run_message = _client_error(
        lambda: ec2.enable_instance_sql_ha_standby_detections(DryRun=True, **instance_kwargs)
    )
    assert dry_run_code == "InvalidInstanceID.Malformed", (
        f"expected InvalidInstanceID.Malformed even under DryRun (instance-ID validation "
        f"runs before the permission check), got {dry_run_code}"
    )
    expected_malformed = f"The instance ID '{fake_instance_id}' is malformed"
    assert dry_run_message == expected_malformed, (
        f"expected message {expected_malformed!r}, got {dry_run_message!r}"
    )

    real_code, real_message = _client_error(
        lambda: ec2.enable_instance_sql_ha_standby_detections(**instance_kwargs)
    )
    assert real_code == "InvalidInstanceID.Malformed", (
        f"expected InvalidInstanceID.Malformed, got {real_code}"
    )
    assert real_message == expected_malformed, (
        f"expected message {expected_malformed!r}, got {real_message!r}"
    )


def _instance_id_kwargs(ec2, fake_instance_id: str) -> dict:
    """Build the instance-id argument for EnableInstanceSqlHaStandbyDetections by
    introspecting the actual request shape via the service model, rather than assuming a
    specific member name/cardinality (scalar vs. list) that may not match the real API."""
    member_name = "InstanceId"
    is_list = False
    op_model = ec2.meta.service_model.operation_model("EnableInstanceSqlHaStandbyDetections")
    input_shape = op_model.input_shape
    if input_shape is not None:
        for name, member_shape in input_shape.members.items():
            if "instance" in name.lower():
                member_name = name
                is_list = member_shape.type_name == "list"
                break
    return {member_name: [fake_instance_id] if is_list else fake_instance_id}


def _client_error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn() and return the (code, message) of the ClientError it raises. A call that succeeds
    raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

