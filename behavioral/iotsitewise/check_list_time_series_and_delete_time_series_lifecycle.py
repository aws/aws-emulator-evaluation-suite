"""list-time-series-and-delete-time-series-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-time-series-and-delete-time-series-lifecycle"
GROUP = "data-plane"
SERVICES = ["iotsitewise"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A disassociated time series created by alias-only ingestion shows up in ListTimeSeries
    (filtered by aliasPrefix/DISASSOCIATED), and DeleteTimeSeries removes it so DescribeTimeSeries
    subsequently 404s."""
    sw = ctx.client("iotsitewise")
    alias = f"/sim2real/{ctx.unique_name('sw-alias').replace('/', '-')}"

    sw.batch_put_asset_property_value(
        entries=[
            {
                "entryId": "e1",
                "propertyAlias": alias,
                "propertyValues": [
                    {"value": {"integerValue": 7}, "timestamp": {"timeInSeconds": int(time.time())}, "quality": "GOOD"}
                ],
            }
        ]
    )
    ctx.on_cleanup(lambda: _safe_delete(sw, alias))

    _poll_until(
        lambda: sw.describe_time_series(alias=alias),
        lambda r: "timeSeriesId" in r,
        timeout_s=60.0,
        interval_s=2.0,
    )

    summaries = sw.list_time_series(aliasPrefix=alias, timeSeriesType="DISASSOCIATED")["TimeSeriesSummaries"]
    aliases = [s["alias"] for s in summaries]
    assert alias in aliases, f"expected {alias!r} in disassociated time series list, got {aliases}"

    sw.delete_time_series(alias=alias)
    final_code, final_message = _poll_until(
        lambda: _describe_time_series_error(sw, alias),
        lambda err: err[0] == "ResourceNotFoundException",
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert final_code == "ResourceNotFoundException"
    expected_message = (
        f"dataAlias with accountId AwsAccountId{{value={ctx.account}}}, "
        f"alias PropertyAlias(super=PropertyAlias{{value={alias}}}) not found"
    )
    assert final_message == expected_message, f"expected message {expected_message!r}, got {final_message!r}"

    redelete_code, redelete_message = _error(lambda: sw.delete_time_series(alias=alias))
    assert redelete_code == "ResourceNotFoundException", (
        f"expected a second delete of the already-deleted alias to 404, got code={redelete_code!r}"
    )
    assert redelete_message == expected_message, (
        f"expected message {expected_message!r}, got {redelete_message!r}"
    )


def _safe_delete(sw, alias):
    try:
        sw.delete_time_series(alias=alias)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


def _describe_time_series_error(sw, alias):
    """Poll probe: (code, message) once DescribeTimeSeries fails, (None, id) while it still reads."""
    try:
        described = sw.describe_time_series(alias=alias)
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    return None, described.get("timeSeriesId")


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = probe()
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            last = None
        if last is not None and predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
