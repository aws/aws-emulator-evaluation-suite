"""get-query-results-schema-for-empty-monitor."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-query-results-schema-for-empty-monitor"
GROUP = "query"
SERVICES = ["internetmonitor"]

# A monitor with no monitored resources rejects StartQuery for every QueryType tried, not
# just one.
REJECTED_QUERY_TYPES = ("MEASUREMENTS", "OVERALL_TRAFFIC_SUGGESTIONS")


def _wait_active(im, name, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = im.get_monitor(MonitorName=name)["Status"]
        if status == "ACTIVE":
            return
        time.sleep(2.0)
    raise AssertionError(f"monitor never became ACTIVE, status={status}")


def _safe_delete_monitor(im, name, timeout_s=60.0):
    """DeleteMonitor requires the monitor be INACTIVE first; transition it, then delete."""
    try:
        im.update_monitor(MonitorName=name, Status="INACTIVE")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status = im.get_monitor(MonitorName=name)["Status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        if status == "INACTIVE":
            break
        time.sleep(2.0)
    im.delete_monitor(MonitorName=name)


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected success raises, so a
    target that accepts what AWS refuses is never read as a code mismatch."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """On a monitor without resources StartQuery fails with BadRequestException "Invalid request body"
    for every QueryType, GetQueryResults for an unminted QueryId fails with ValidationException
    "Invalid query ID provided", and the monitor stays ACTIVE."""
    im = ctx.client("internetmonitor")
    name = ctx.unique_name("sim2real-im-qres-")
    im.create_monitor(
        MonitorName=name, TrafficPercentageToMonitor=100, MaxCityNetworksToMonitor=500,
        Tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: _safe_delete_monitor(im, name))
    _wait_active(im, name)

    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=1)
    for query_type in REJECTED_QUERY_TYPES:
        code, message = _error(
            lambda qt=query_type: im.start_query(
                MonitorName=name, StartTime=start, EndTime=end, QueryType=qt, FilterParameters=[]
            )
        )
        assert code == "BadRequestException", (
            f"expected BadRequestException for StartQuery({query_type}) against a resourceless "
            f"monitor, got: {code}"
        )
        assert message == "Invalid request body", (
            f"StartQuery({query_type}) against a resourceless monitor: unexpected message {message!r}"
        )

    bogus_query_id = "00000000-0000-4000-8000-000000000000"
    code, message = _error(lambda: im.get_query_results(MonitorName=name, QueryId=bogus_query_id))
    assert code == "ValidationException", f"expected ValidationException for bogus QueryId, got: {code}"
    assert message == "Invalid query ID provided", f"unexpected message for bogus QueryId: {message!r}"

    # Positive control: the monitor itself is real and reachable throughout.
    still_there = im.get_monitor(MonitorName=name)
    assert still_there["Status"] == "ACTIVE", f"monitor unexpectedly not ACTIVE: {still_there['Status']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
