"""delete-time-series-missing-identifier-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-time-series-missing-identifier-rejected"
GROUP = "overly-permissive"
SERVICES = ["iotsitewise"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteTimeSeries called with neither alias nor assetId+propertyId is rejected with
    InvalidRequestException and leaves an existing time series untouched; deleting it properly by
    alias succeeds."""
    client = ctx.client("iotsitewise")
    alias = ctx.unique_name("/sim2real/behav/orphan-")
    now = int(time.time())
    client.batch_put_asset_property_value(entries=[{
        "entryId": "e1",
        "propertyAlias": alias,
        "propertyValues": [
            {"value": {"doubleValue": 1.0}, "timestamp": {"timeInSeconds": now, "offsetInNanos": 0}, "quality": "GOOD"}
        ],
    }])
    ctx.on_cleanup(lambda: _safe(lambda: client.delete_time_series(alias=alias)))
    _poll_time_series_exists(client, alias)

    code, message = _error(lambda: client.delete_time_series())
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got code={code!r}"
    assert message == "Please provide either alias or assetId and propertyId", f"unexpected message: {message!r}"

    # effect absent: the time series is still there
    client.describe_time_series(alias=alias)

    # positive control: deleting it properly (by alias) succeeds
    client.delete_time_series(alias=alias)
    _poll_time_series_gone(client, alias)


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_time_series_exists(client, alias, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            return client.describe_time_series(alias=alias)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(interval_s)
    raise AssertionError("time series never became visible")


def _poll_time_series_gone(client, alias, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            client.describe_time_series(alias=alias)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError("time series was never deleted")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
