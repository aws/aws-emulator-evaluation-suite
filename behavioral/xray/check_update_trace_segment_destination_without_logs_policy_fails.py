"""update-trace-segment-destination-without-logs-policy-fails."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "update-trace-segment-destination-without-logs-policy-fails"
GROUP = 'overly-permissive'
SERVICES = ['xray']

_POLICY_NAME = "sim2real-xray-utsd-wlp-policy"


def _error_code(fn):
    """Call fn() and return its botocore (code, message); raise if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"].get("Code"), exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected UpdateTraceSegmentDestination to be refused, but it SUCCEEDED: {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:logs-resource-policy", "resource:account-singleton:xray-trace-segment-destination")
def run(ctx) -> None:
    """Switching to CloudWatchLogs without a Logs policy granting X-Ray PutLogEvents fails with
    AccessDeniedException and leaves the destination unchanged; the same call succeeds once the
    policy exists, so the refusal is specific to the missing policy.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Enable-TransactionSearch.html
    """
    xr = ctx.client("xray")
    logs = ctx.client("logs")

    settled = _settled_trace_segment_destination(xr, timeout_s=600.0)
    current = settled.get("Destination", "XRay")
    if current != "XRay":
        raise AssertionError(
            f"account destination is already {current}; the unconfigured-policy precondition "
            "cannot be exercised"
        )
    # Registered before any switch: the destination is account-wide and must be put back even if
    # a failure or timeout happens before the `finally` below.
    ctx.on_cleanup(lambda: _restore_trace_segment_destination(xr, current, timeout_s=600.0))

    code, message = _error_code(
        lambda: xr.update_trace_segment_destination(Destination="CloudWatchLogs")
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    expected_message = (
        "XRay does not have permission to call PutLogEvents on the aws/spans Log Group. Please "
        "verify that your CloudWatch Logs Resource Policies are configured correctly"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    after = xr.get_trace_segment_destination()
    assert after.get("Destination") == "XRay", (
        f"rejected update still changed destination to {after.get('Destination')}"
    )

    # The policy the Transaction Search docs require; the identical call must now succeed.
    account = ctx.client("sts").get_caller_identity()["Account"]
    region = ctx.region
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "UpdateTraceSegmentDestinationWithoutLogsPolicyFailsControl",
                "Effect": "Allow",
                "Principal": {"Service": "xray.amazonaws.com"},
                "Action": "logs:PutLogEvents",
                "Resource": [
                    f"arn:aws:logs:{region}:{account}:log-group:aws/spans:*",
                    f"arn:aws:logs:{region}:{account}:log-group:/aws/application-signals/data:*",
                ],
                "Condition": {
                    "ArnLike": {"aws:SourceArn": f"arn:aws:xray:{region}:{account}:*"},
                    "StringEquals": {"aws:SourceAccount": account},
                },
            }
        ],
    }
    logs.put_resource_policy(policyName=_POLICY_NAME, policyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: _safe_delete_resource_policy(logs, _POLICY_NAME))

    try:
        xr.update_trace_segment_destination(Destination="CloudWatchLogs")

        restored = _settled_trace_segment_destination(xr, timeout_s=600.0)
        assert restored.get("Destination") == "CloudWatchLogs", (
            f"the identical call succeeded but the destination reads back as "
            f"{restored.get('Destination')!r}, not CloudWatchLogs"
        )
    finally:
        # Restore synchronously so the account is not left mid-transition or pointing at
        # CloudWatchLogs after its delivery policy is deleted.
        _restore_trace_segment_destination(xr, current, timeout_s=600.0)
        final = xr.get_trace_segment_destination()
        assert final.get("Destination") == "XRay", (
            f"failed to restore the account destination to XRay, left at {final.get('Destination')!r}"
        )


def _safe_delete_resource_policy(logs, policy_name: str) -> None:
    try:
        logs.delete_resource_policy(policyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _settled_trace_segment_destination(xray, *, timeout_s: float) -> dict:
    # AWS refuses UpdateTraceSegmentDestination while a previous switch is still PENDING.
    deadline = time.monotonic() + timeout_s
    while True:
        current = xray.get_trace_segment_destination()
        if current.get("Status") == "ACTIVE":
            return current
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"trace-segment destination still not ACTIVE after {timeout_s}s: {current!r}"
            )
        time.sleep(2)


def _restore_trace_segment_destination(xray, original: str, *, timeout_s: float) -> None:
    """Switch the destination back to `original` and wait until it is ACTIVE again."""
    if _settled_trace_segment_destination(xray, timeout_s=timeout_s)["Destination"] != original:
        xray.update_trace_segment_destination(Destination=original)
        _settled_trace_segment_destination(xray, timeout_s=timeout_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
