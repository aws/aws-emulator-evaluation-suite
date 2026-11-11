"""describe-quota-share-unknown-fails."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-quota-share-unknown-fails"
GROUP = "error-semantics"
SERVICES = ["batch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeQuotaShare rejects an ARN lacking job-queue/quota-share segments as a pattern
    violation, with a message distinct from the 'does not exist' ClientException a well-formed
    nonexistent ARN gets."""
    batch = ctx.client("batch")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # positive control: well-formed ARN shape (job-queue/.../quota-share/...) that
    # simply does not exist is rejected as "does not exist", not as a pattern error.
    wellformed_arn = (
        f"arn:aws:batch:{ctx.region}:{account_id}:job-queue/"
        f"{ctx.unique_name('sim2real-behav-qs-jq-')}/quota-share/"
        f"{ctx.unique_name('sim2real-behav-qs-')}"
    )
    control_code, control_message, _ = _error_code(lambda: batch.describe_quota_share(quotaShareArn=wellformed_arn))
    assert control_code == "ClientException", (
        f"expected ClientException for a well-formed but nonexistent quota share, got {control_code!r}"
    )
    expected_control = f"{wellformed_arn} does not exist."
    assert control_message == expected_control, (
        f"expected message {expected_control!r} for a well-formed but nonexistent quota share, got {control_message!r}"
    )

    # break exactly one thing: an ARN with no job-queue/quota-share path segments at
    # all. Malformed by construction, so there is no restore leg (it can never become
    # a valid ARN).
    malformed_arn = f"arn:aws:batch:{ctx.region}:{account_id}:quota-share/{ctx.unique_name('sim2real-behav-qs-')}"
    code, message, request_id = _error_code(lambda: batch.describe_quota_share(quotaShareArn=malformed_arn))
    assert code == "ClientException", f"expected ClientException for a malformed quota share arn, got {code!r}"
    # Batch embeds the call's own request id in this message.
    expected = (
        "Error executing request, Exception : Quota Share arn should match a valid Quota Share "
        f"arn pattern, RequestId: {request_id}"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    assert message != control_message, (
        "malformed-arn and nonexistent-arn rejections must not collapse to the identical message"
    )


def _error_code(fn):
    """Call fn(); return (Error.Code, Error.Message, RequestId) of the ClientError it raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return (
            err.response["Error"]["Code"],
            err.response["Error"].get("Message"),
            err.response.get("ResponseMetadata", {}).get("RequestId"),
        )
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
