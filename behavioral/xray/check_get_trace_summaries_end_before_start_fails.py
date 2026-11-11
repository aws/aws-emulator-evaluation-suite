"""get-trace-summaries-end-before-start-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-trace-summaries-end-before-start-fails"
GROUP = 'overly-permissive'
SERVICES = ['xray']


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetTraceSummaries rejects a time window where EndTime precedes StartTime, distinct from
    every other GetTraceSummaries call failing outright: the same call shape with a valid
    (StartTime, EndTime) ordering succeeds first (positive control)."""
    xr = ctx.client("xray")
    now = time.time()

    # Positive control: identical call shape, a valid (ascending) time window.
    resp = xr.get_trace_summaries(StartTime=now - 3600, EndTime=now)
    assert "TraceSummaries" in resp, f"expected a TraceSummaries key in the response, got {resp!r}"

    code, message = _error(
        lambda: xr.get_trace_summaries(StartTime=now, EndTime=now - 3600)
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    assert message == "End time cannot be earlier than start time", (
        f"unexpected message: {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
