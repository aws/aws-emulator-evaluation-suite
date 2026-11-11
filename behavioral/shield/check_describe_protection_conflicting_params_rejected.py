"""describe-protection-conflicting-params-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-protection-conflicting-params-rejected"
GROUP = "overly-permissive"
SERVICES = ["shield"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeProtection with both ProtectionId and ResourceArn is rejected with InvalidParameterException and
    the exact message, while ProtectionId alone falls through to ResourceNotFoundException "The subscription
    does not exist." on an unsubscribed account.
    """
    shield = ctx.client("shield")
    bogus_protection_id = "12345678-1234-1234-1234-123456789012"
    bogus_resource_arn = f"arn:aws:ec2:{ctx.region}:111122223333:eip-allocation/eipalloc-{'0' * 17}"

    # Break exactly one thing: pass both mutually-exclusive identifiers.
    both_code, both_message = _error_code(
        lambda: shield.describe_protection(ProtectionId=bogus_protection_id, ResourceArn=bogus_resource_arn)
    )
    assert both_code == "InvalidParameterException", f"expected InvalidParameterException, got {both_code!r}"
    assert both_message == (
        "Invalid parameter. You must provide one value, either protectionId or resourceArn, but not both."
    ), f"unexpected message {both_message!r}"

    # Positive control: a single, well-formed identifier is accepted and processed (falls through
    # to "not found" rather than the parameter-conflict error), proving the rejection above was
    # about the conflicting combination and not a generally-broken API path.
    single_code, single_message = _error_code(lambda: shield.describe_protection(ProtectionId=bogus_protection_id))
    assert single_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {single_code!r}"
    assert single_message == "The subscription does not exist.", f"unexpected message {single_message!r}"


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
