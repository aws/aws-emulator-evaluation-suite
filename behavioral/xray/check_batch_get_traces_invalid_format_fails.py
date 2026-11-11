"""batch-get-traces-invalid-format-fails."""
from __future__ import annotations

import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-get-traces-invalid-format-fails"
GROUP = 'overly-permissive'
SERVICES = ['xray']


def _hex(n: int) -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


def new_trace_id(epoch_seconds: float | None = None) -> str:
    """Generate a syntactically valid X-Ray trace ID: 1-<8 hex>-<24 hex>."""
    ts = int(epoch_seconds if epoch_seconds is not None else time.time())
    return f"1-{ts:08x}-{_hex(24)}"


def _client_error(fn):
    """The AWS Error dict raised by fn(). Raises if fn() unexpectedly succeeds, so acceptance
    never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"expected the malformed trace id to be refused, but the call SUCCEEDED and returned "
        f"{result!r}"
    )


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A syntactically invalid trace ID fails BatchGetTraces with InvalidRequestException, while
    a well-formed unknown ID returns a plain 200 before and after (positive control)."""
    xr = ctx.client("xray")

    # Positive control: a well-formed trace id that simply does not exist must succeed with a
    # plain 200, not raise -- otherwise "rejects a malformed id" would be indistinguishable from
    # "rejects every BatchGetTraces call".
    well_formed_unknown_id = new_trace_id()
    control = xr.batch_get_traces(TraceIds=[well_formed_unknown_id])
    assert control.get("Traces", []) == [], (
        f"a well-formed unknown trace id must not materialize a trace: {control!r}"
    )
    assert control.get("UnprocessedTraceIds", []) == [], (
        f"a well-formed unknown trace id must be silently omitted, not reported: {control!r}"
    )

    # Break exactly one thing: swap the well-formed id for a syntactically invalid one.
    error = _client_error(lambda: xr.batch_get_traces(TraceIds=["not-a-trace-id"]))
    assert error.get("Code") == "InvalidRequestException", (
        f"expected InvalidRequestException, got {error!r}"
    )
    assert error.get("Message") == "Invalid trace id not-a-trace-id: incorrect id format", (
        f"the refusal must name the malformed id and the format rule, got {error!r}"
    )

    # Positive control, after the refusal: the identical well-formed call still succeeds, so the
    # rejection above did not wedge the API.
    again = xr.batch_get_traces(TraceIds=[well_formed_unknown_id])
    assert again.get("Traces", []) == [], again
    assert again.get("UnprocessedTraceIds", []) == [], again


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
