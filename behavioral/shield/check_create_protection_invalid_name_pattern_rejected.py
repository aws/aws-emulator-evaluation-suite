"""create-protection-invalid-name-pattern-rejected."""
from __future__ import annotations

import re
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-protection-invalid-name-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["shield"]


# AWS appends the request id of the inner service call to this message; it is the only part
# that varies per call.
_REQUEST_ID = re.compile(r"Request ID: [0-9A-Za-z-]+")


def _stable(message):
    if message is None:
        return None
    return _REQUEST_ID.sub("Request ID: <request-id>", message)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateProtection with a Name outside the documented pattern is rejected with ValidationException and the
    exact message, while the same request with a valid Name moves on to InvalidResourceException for the
    unknown EIP, so the rejection is about the Name.
    """
    shield = ctx.client("shield")
    fake_resource_arn = f"arn:aws:ec2:{ctx.region}:111122223333:eip-allocation/eipalloc-{'0' * 17}"

    invalid_name = "bad!name@@"
    bad_code, bad_message = _error_code(
        lambda: shield.create_protection(Name=invalid_name, ResourceArn=fake_resource_arn)
    )
    assert bad_code == "ValidationException", f"expected ValidationException, got {bad_code!r}"
    assert bad_message == "Error validating the following inputs: name", f"unexpected message {bad_message!r}"

    valid_name = ctx.unique_name("sim2real-shield-ctrl-")
    ctrl_code, ctrl_message = _error_code(
        lambda: shield.create_protection(Name=valid_name, ResourceArn=fake_resource_arn)
    )
    assert ctrl_code == "InvalidResourceException", f"expected InvalidResourceException, got {ctrl_code!r}"
    # The message relays Shield's internal EC2 lookup, whose request id is the only varying part.
    eip_region = fake_resource_arn.split(":")[3]
    allocation_id = fake_resource_arn.rsplit("/", 1)[1]
    expected_ctrl = (
        f"Failed to validate EIP resource: {fake_resource_arn} in region: {eip_region}, error: The "
        f"allocation ID '{allocation_id}' does not exist (Service: AmazonEC2; Status Code: 400; "
        "Error Code: InvalidAllocationID.NotFound; Request ID: <request-id>; Proxy: null)"
    )
    assert _stable(ctrl_message) == expected_ctrl, f"expected message {expected_ctrl!r}, got {ctrl_message!r}"


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
