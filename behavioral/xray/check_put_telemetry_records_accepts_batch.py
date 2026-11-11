"""put-telemetry-records-accepts-batch."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "put-telemetry-records-accepts-batch"
GROUP = 'trace-data-plane'
SERVICES = ['xray']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutTelemetryRecords accepts a batch of three well-formed records in one call and answers
    with the empty result, nothing beside the response metadata."""
    xr = ctx.client("xray")
    now = time.time()
    hostname = ctx.unique_name("sim2real-behav-host-")
    records = [
        {
            "Timestamp": now - offset,
            "SegmentsReceivedCount": count,
            "SegmentsSentCount": count,
            "SegmentsSpilloverCount": 0,
            "SegmentsRejectedCount": 0,
        }
        for offset, count in ((2.0, 3), (1.0, 5), (0.0, 1))
    ]
    resp = xr.put_telemetry_records(
        TelemetryRecords=records,
        EC2InstanceId="i-" + "0" * 17,
        Hostname=hostname,
    )
    # A refused batch raises; an accepted one returns the modeled empty result, so any member
    # beside the response metadata is a per-record verdict AWS never returns.
    assert set(resp) == {"ResponseMetadata"}, (
        f"expected a batch of {len(records)} well-formed telemetry records to be accepted with "
        f"the empty PutTelemetryRecordsResult for hostname {hostname!r}, got {resp!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
