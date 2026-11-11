"""start-trace-retrieval-invalid-time-range-rejected."""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-trace-retrieval-invalid-time-range-rejected"
GROUP = "error-semantics"
SERVICES = ["xray"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartTraceRetrieval with EndTime before StartTime fails with InvalidRequestException "...
    End time cannot be earlier than start time", while the same trace ID with an ordered range
    is not refused that way."""
    xray = ctx.client("xray")
    now = datetime.now(timezone.utc)
    trace_id = _trace_id(int((now - timedelta(minutes=5)).timestamp()))

    # Break exactly one thing: EndTime precedes StartTime.
    bad_start = now
    bad_end = now - timedelta(hours=1)
    code, message = _error_code(
        lambda: xray.start_trace_retrieval(
            TraceIds=[trace_id], StartTime=bad_start, EndTime=bad_end
        )
    )
    assert code == "InvalidRequestException", f"unexpected error code: {code}"
    expected_message = (
        "Input parameters invalid for request. End time cannot be earlier than start time"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Positive control: identical trace ID, well-formed time range (StartTime <=
    # EndTime) -- must NOT raise InvalidRequestException. Whatever happens next (a
    # successful SCHEDULED retrieval, or a ResourceNotFoundException because this
    # particular trace ID was never ingested) is a different, more specific error than
    # the time-ordering violation we are testing for.
    good_start = now - timedelta(minutes=5)
    good_end = now
    good_code = None
    try:
        resp = xray.start_trace_retrieval(
            TraceIds=[trace_id], StartTime=good_start, EndTime=good_end
        )
    except Exception as err:  # noqa: BLE001
        good_code = getattr(err, "response", {}).get("Error", {}).get("Code")
    else:
        token = resp["RetrievalToken"]
        ctx.on_cleanup(lambda: _safe_cancel(xray, token))
        list_resp = xray.list_retrieved_traces(RetrievalToken=token, TraceFormat="XRAY")
        assert list_resp["RetrievalStatus"] in (
            "SCHEDULED",
            "RUNNING",
            "COMPLETE",
            "FAILED",
            "CANCELLED",
            "TIMEOUT",
        )
    assert good_code != "InvalidRequestException", (
        f"well-formed time range still raised InvalidRequestException: {good_code!r} "
        "-- the rejection was not specific to the broken time ordering"
    )


def _trace_id(epoch_seconds: int) -> str:
    return f"1-{epoch_seconds:08x}-{random.getrandbits(96):024x}"


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
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
