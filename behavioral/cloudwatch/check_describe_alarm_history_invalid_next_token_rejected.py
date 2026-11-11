"""describe-alarm-history-invalid-next-token-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-alarm-history-invalid-next-token-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeAlarmHistory with a garbage NextToken fails with InvalidNextToken "Invalid
    NextToken : <token>", while the same call without a token returns AlarmHistoryItems."""
    cw = ctx.client("cloudwatch")

    control = cw.describe_alarm_history()
    assert "AlarmHistoryItems" in control, (
        f"positive control: DescribeAlarmHistory with no NextToken must succeed, got {control!r}"
    )

    code, message = _client_error(
        lambda: cw.describe_alarm_history(NextToken="sim2real-behav-not-a-real-token==")
    )
    assert code == "InvalidNextToken", f"expected InvalidNextToken, got {code!r}"
    expected_message = "Invalid NextToken : sim2real-behav-not-a-real-token=="
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _client_error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"real AWS rejects a garbled NextToken, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
