"""describe-instance-associations-status-invalid-instance-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-instance-associations-status-invalid-instance-rejected"
GROUP = "overly-permissive"
SERVICES = ["ssm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeInstanceAssociationsStatus with a malformed instance id is rejected with
    ValidationException rather than returning an empty result, while a syntactically valid
    (if unregistered) instance id still returns a normal, empty result."""
    ssm = ctx.client("ssm")

    # positive control: a well-formed but unregistered instance id returns an empty result
    control = ssm.describe_instance_associations_status(InstanceId="i-0123456789abcdef0")
    infos = control.get("InstanceAssociationStatusInfos")
    assert infos == [], (
        f"expected an empty InstanceAssociationStatusInfos for an unregistered instance, got {infos!r}"
    )

    # break exactly one thing: an instance id that doesn't match the required id pattern
    bad_instance_id = "not-a-valid-instance-id"
    code, message = _error(
        lambda: ssm.describe_instance_associations_status(InstanceId=bad_instance_id)
    )
    assert code == "ValidationException", (
        f"expected ValidationException for a malformed instance id, got {code!r}"
    )
    assert message == (
        f"2 validation errors detected: Value '{bad_instance_id}' at 'instanceId' failed to satisfy "
        "constraint: Member must have length less than or equal to 20; "
        f"Value '{bad_instance_id}' at 'instanceId' failed to satisfy constraint: "
        r"Member must satisfy regular expression pattern: (^i-(\w{8}|\w{17})$)|(^mi-\w{17}$)"
    ), message


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected describe_instance_associations_status to be rejected, it succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
