"""create-endpoint-invalid-subnet-id-format-validation-error."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-endpoint-invalid-subnet-id-format-validation-error"
GROUP = "validation"
SERVICES = ["s3outposts"]

VALIDATION_PREFIX = "1 validation error detected: Value '{}' at '{}' failed to satisfy constraint: "
SUBNET_ID_PATTERN = r"^subnet-([0-9a-f]{8}|[0-9a-f]{17})$"
OUTPOST_NOT_FOUND = "The specified outpost does not exist, or does not have S3 capacity provisioned on it."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateEndpoint rejects a malformed SubnetId with ValidationException -- distinct from
    the ResourceNotFoundException a well-formed but unknown Outpost/subnet combination gets."""
    s3o = ctx.client("s3outposts")
    outpost_id = "999999999999"
    sg_id = "sg-" + "0" * 8

    bad_code, bad_message = _error(
        lambda: s3o.create_endpoint(
            OutpostId=outpost_id, SubnetId="bad-subnet-id", SecurityGroupId=sg_id
        )
    )
    assert bad_code == "ValidationException", (
        f"expected ValidationException for a malformed SubnetId, got {bad_code!r}"
    )
    expected = VALIDATION_PREFIX.format("bad-subnet-id", "subnetId") + (
        "Member must satisfy regular expression pattern: " + SUBNET_ID_PATTERN
    )
    assert bad_message == expected, f"message={bad_message!r}"

    # Positive control: identical, well-formed request shape must fail differently, proving
    # the ValidationException above was specific to the malformed SubnetId pattern.
    control_code, control_message = _error(
        lambda: s3o.create_endpoint(
            OutpostId=outpost_id, SubnetId="subnet-" + "0" * 8, SecurityGroupId=sg_id
        )
    )
    assert control_code == "ResourceNotFoundException", (
        "expected ResourceNotFoundException for a well-formed but unknown SubnetId, "
        f"got {control_code!r}"
    )
    assert control_message == OUTPOST_NOT_FOUND, f"message={control_message!r}"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
