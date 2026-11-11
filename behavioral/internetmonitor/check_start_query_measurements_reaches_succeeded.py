"""start-query-measurements-reaches-succeeded."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-query-measurements-reaches-succeeded"
GROUP = "query"
SERVICES = ["internetmonitor"]


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


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartQuery MEASUREMENTS on a monitor without resources fails with BadRequestException "Invalid
    request body" (there is no data to query), and the monitor stays ACTIVE."""
    im = ctx.client("internetmonitor")
    name = ctx.unique_name("sim2real-im-query-")
    im.create_monitor(
        MonitorName=name,
        TrafficPercentageToMonitor=100,
        MaxCityNetworksToMonitor=500,
        Tags={"team": "sim2real"},
    )
    ctx.on_cleanup(lambda: _safe_delete_monitor(im, name))
    _wait_active(im, name)

    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=1)

    from botocore.exceptions import ClientError

    try:
        result = im.start_query(
            MonitorName=name, StartTime=start, EndTime=end, QueryType="MEASUREMENTS", FilterParameters=[]
        )
    except ClientError as err:
        raised, message = err.response["Error"]["Code"], err.response["Error"].get("Message")
    else:
        raise AssertionError(f"expected StartQuery to be rejected, but it succeeded and returned {result!r}")
    assert raised == "BadRequestException", f"expected BadRequestException, got: {raised}"
    assert message == "Invalid request body", f"unexpected message: {message!r}"

    # The failed StartQuery attempt must not have perturbed the monitor's own state.
    status = im.get_monitor(MonitorName=name)["Status"]
    assert status == "ACTIVE", f"monitor state corrupted by failed StartQuery, status={status}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
