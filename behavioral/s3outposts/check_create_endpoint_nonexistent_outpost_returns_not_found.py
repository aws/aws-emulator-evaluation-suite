"""create-endpoint-nonexistent-outpost-returns-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-endpoint-nonexistent-outpost-returns-not-found"
GROUP = "error-semantics"
SERVICES = ["s3outposts"]

VALIDATION_PREFIX = "1 validation error detected: Value '{}' at '{}' failed to satisfy constraint: "
OUTPOST_ID_PATTERN = r"^(op-[a-f0-9]{17}|\d{12}|ec2)$"
OUTPOST_NOT_FOUND = "The specified outpost does not exist, or does not have S3 capacity provisioned on it."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateEndpoint with a malformed OutpostId is ValidationException with the exact pattern message,
    while a well-formed but unknown OutpostId with the same subnet and security group is
    ResourceNotFoundException with the exact message, and no endpoint is listed for it."""
    s3o = ctx.client("s3outposts")
    subnet_id = "subnet-" + "a" * 8
    sg_id = "sg-" + "a" * 8

    control_code, control_message = _error(
        lambda: s3o.create_endpoint(
            OutpostId="not-a-valid-outpost-id", SubnetId=subnet_id, SecurityGroupId=sg_id
        )
    )
    assert control_code == "ValidationException", (
        f"expected ValidationException for a malformed OutpostId, got {control_code}"
    )
    expected = VALIDATION_PREFIX.format("not-a-valid-outpost-id", "outpostId") + (
        "Member must satisfy regular expression pattern: " + OUTPOST_ID_PATTERN
    )
    assert control_message == expected, f"message={control_message!r}"

    # A placeholder 12-digit account-style Outpost id; matches the \d{12} branch of the
    # OutpostId pattern but is not an Outpost owned by or shared with this account.
    outpost_id = "111122223333"
    code, message = _error(
        lambda: s3o.create_endpoint(
            OutpostId=outpost_id, SubnetId=subnet_id, SecurityGroupId=sg_id
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a well-formed but unknown OutpostId, got {code}"
    )
    assert message == OUTPOST_NOT_FOUND, f"message={message!r}"

    endpoints = s3o.list_endpoints(MaxResults=100)["Endpoints"]
    assert all(ep.get("OutpostsId") != outpost_id for ep in endpoints), (
        f"an endpoint was recorded against the nonexistent outpost {outpost_id}"
    )


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
