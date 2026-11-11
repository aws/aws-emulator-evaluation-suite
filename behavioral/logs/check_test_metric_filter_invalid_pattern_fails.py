"""test-metric-filter-invalid-pattern-fails."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "test-metric-filter-invalid-pattern-fails"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TestMetricFilter with a malformed filter pattern (unbalanced bracket)
    raises InvalidParameterException rather than returning an empty/garbage
    match list."""
    logs = ctx.client("logs")
    sample_events = ["127.0.0.1 - frank [10/Oct/2000:13:25:15 -0700]"]

    # positive control: a well-formed pattern against this account/credentials
    # succeeds first, so the rejection below is attributable to the malformed
    # pattern and not to a broken client or a service that refuses everything.
    control = logs.test_metric_filter(
        filterPattern='[ip, identity, user_id]',
        logEventMessages=sample_events,
    )
    assert control["matches"], f"expected the positive control to match, got {control['matches']}"

    code, message = _client_error(
        lambda: logs.test_metric_filter(
            filterPattern="[ip, identity, user_id",  # unbalanced bracket
            logEventMessages=sample_events,
        )
    )
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for TestMetricFilter with a malformed "
        f"filter pattern, got {code}"
    )
    assert message == "If a filter pattern starts with '[' it must end with ']'", (
        f"unexpected InvalidParameterException message for the malformed pattern: {message!r}"
    )


def _client_error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
