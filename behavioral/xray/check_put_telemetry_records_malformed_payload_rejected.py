"""put-telemetry-records-malformed-payload-rejected."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-telemetry-records-malformed-payload-rejected"
GROUP = "negative-classes"
SERVICES = ["xray"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutTelemetryRecords with string-typed segment counters fails with SerializationException and
    the exact message, while a well-formed batch of the same shape returns 200."""
    xray = ctx.client("xray")
    # Parameter validation is off so the wrong-typed counters reach the service.
    lenient = ctx.client("xray", config=Config(parameter_validation=False))
    now = datetime.now(timezone.utc)

    malformed_records = [
        {
            "Timestamp": now,
            "SegmentsReceivedCount": "not-a-number",
            "SegmentsSentCount": "also-not-a-number",
            "SegmentsSpilloverCount": "still-not-a-number",
            "SegmentsRejectedCount": "definitely-not-a-number",
        }
    ]
    code, message = _error(
        lambda: lenient.put_telemetry_records(TelemetryRecords=malformed_records)
    )
    assert code == "SerializationException", f"CODE={code}"
    assert message == "STRING_VALUE can not be converted to an Integer", (
        f"unexpected message: {message!r}"
    )

    well_formed_records = [
        {
            "Timestamp": now,
            "SegmentsReceivedCount": 3,
            "SegmentsSentCount": 3,
            "SegmentsSpilloverCount": 0,
            "SegmentsRejectedCount": 0,
        }
    ]
    resp = xray.put_telemetry_records(TelemetryRecords=well_formed_records)
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected the structurally well-formed positive control to be accepted, got {resp!r}"
    )


def _error(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn(); return its error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
