"""start-trace-retrieval-malformed-time-format-fails."""
from __future__ import annotations

import random
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-trace-retrieval-malformed-time-format-fails"
GROUP = "overly-permissive"
SERVICES = ["xray"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartTraceRetrieval with times scaled 1000x (milliseconds sent as seconds) fails with
    InvalidRequestException "... End time should not be before the service was generally
    available.", while a sane window is not refused that way."""
    xray = ctx.client("xray")
    now = datetime.now(timezone.utc)
    # Non-empty, syntactically well-formed trace ID -- an empty TraceIds array is rejected on
    # its own regardless of the time values, which would mask the time-format-specific
    # rejection this check targets.
    trace_id = _trace_id(int((now - timedelta(minutes=5)).timestamp()))

    # A fixed 1976 anchor keeps the x1000-scaled value inside Python's datetime range (year
    # 9999), so the request reaches the service; scaling today's clock fails in the SDK first.
    anchor_s = 200_000_000
    bogus_start = anchor_s * 1000
    bogus_end = bogus_start + 3_600_000  # +1 "hour" in the same (wrong) units
    code, message = _error_code(
        lambda: xray.start_trace_retrieval(
            TraceIds=[trace_id], StartTime=bogus_start, EndTime=bogus_end
        )
    )
    assert code == "InvalidRequestException", (
        f"expected InvalidRequestException for a millisecond-scale time value landing "
        f"thousands of years in the future, got {code!r}"
    )
    expected_message = (
        "Invalid input parameters for starting trace retrieval.End time should not be before "
        "the service was generally available."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # positive control (same file, same trace ID): a sane epoch-seconds window does NOT fail
    # this same validation path (it may still fail for an unrelated reason, e.g. Transaction
    # Search not configured, but never for the time-format problem above).
    good_start = now - timedelta(minutes=5)
    good_end = now
    control_code = None
    try:
        resp = xray.start_trace_retrieval(
            TraceIds=[trace_id], StartTime=good_start, EndTime=good_end
        )
    except ClientError as err:
        control_code = err.response["Error"]["Code"]
    else:
        token = resp["RetrievalToken"]
        ctx.on_cleanup(lambda: _safe_cancel(xray, token))
    assert control_code != "InvalidRequestException", (
        f"sane epoch-seconds window unexpectedly failed the same validation: {control_code!r}"
    )


def _trace_id(epoch_seconds: int) -> str:
    return f"1-{epoch_seconds:08x}-{random.getrandbits(96):024x}"


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe_cancel(xray, token: str) -> None:
    try:
        xray.cancel_trace_retrieval(RetrievalToken=token)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
