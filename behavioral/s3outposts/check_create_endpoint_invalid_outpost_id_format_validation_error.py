"""create-endpoint-invalid-outpost-id-format-validation-error."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-endpoint-invalid-outpost-id-format-validation-error"
GROUP = "validation"
SERVICES = ["s3outposts"]

VALIDATION_PREFIX = "1 validation error detected: Value '{}' at '{}' failed to satisfy constraint: "
OUTPOST_ID_PATTERN = r"^(op-[a-f0-9]{17}|\d{12}|ec2)$"
ACCESS_DENIED = "Access Denied"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateEndpoint rejects a malformed OutpostId with ValidationException -- distinct from
    the ResourceNotFoundException a well-formed but unknown OutpostId gets."""
    s3o = ctx.client("s3outposts")
    subnet_id = "subnet-" + "0" * 8
    sg_id = "sg-" + "0" * 8

    bad_code, bad_message = _error(
        lambda: s3o.create_endpoint(
            OutpostId="not-a-valid-outpost-id", SubnetId=subnet_id, SecurityGroupId=sg_id
        )
    )
    assert bad_code == "ValidationException", (
        f"expected ValidationException for a malformed OutpostId, got {bad_code!r}"
    )
    expected = VALIDATION_PREFIX.format("not-a-valid-outpost-id", "outpostId") + (
        "Member must satisfy regular expression pattern: " + OUTPOST_ID_PATTERN
    )
    assert bad_message == expected, f"message={bad_message!r}"

    # Positive control: identical, well-formed request shape but referencing an Outpost that
    # does not exist must fail differently -- this proves the ValidationException above came
    # from the malformed OutpostId pattern, not from a backend that unconditionally rejects
    # the call regardless of input.
    control_code, control_message = _error(
        lambda: s3o.create_endpoint(
            OutpostId="op-" + "0" * 17, SubnetId=subnet_id, SecurityGroupId=sg_id
        )
    )
    assert control_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a well-formed but unknown OutpostId, "
        f"got {control_code!r}"
    )
    assert control_message == ACCESS_DENIED, f"message={control_message!r}"


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
