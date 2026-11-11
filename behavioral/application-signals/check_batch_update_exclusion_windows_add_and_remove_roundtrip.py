"""batch-update-exclusion-windows-add-and-remove-roundtrip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-update-exclusion-windows-add-and-remove-roundtrip"
GROUP = "state"
SERVICES = ["application-signals"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Adding an exclusion window makes it visible via ListServiceLevelObjectiveExclusionWindows;
    removing the exact same window clears it again."""
    sig = ctx.client("application-signals")
    name = ctx.unique_name("sim2real-slo-")
    namespace = "Sim2RealBehavioral"
    metric_name = "ReqCount" + name.replace("-", "")

    created = sig.create_service_level_objective(
        Name=name,
        RequestBasedSliConfig=_request_based_sli_config(namespace, metric_name),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Slo"]
    arn = created["Arn"]
    ctx.on_cleanup(lambda: _delete_slo_ignore_missing(sig, arn))

    initial_windows = sig.list_service_level_objective_exclusion_windows(Id=arn)["ExclusionWindows"]
    assert initial_windows == [], f"expected no exclusion windows on a fresh SLO, got {initial_windows!r}"

    import datetime as _dt

    start_time = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0) + _dt.timedelta(
        minutes=10
    )
    window_to_add = {
        "Window": {"DurationUnit": "HOUR", "Duration": 2},
        "Reason": "sim2real-maintenance-window",
        "StartTime": start_time,
    }
    update_resp = sig.batch_update_exclusion_windows(
        SloIds=[arn],
        AddExclusionWindows=[window_to_add],
    )
    assert update_resp["Errors"] == [], f"expected AddExclusionWindows to succeed, got errors {update_resp['Errors']!r}"

    after_add = sig.list_service_level_objective_exclusion_windows(Id=arn)["ExclusionWindows"]
    assert len(after_add) == 1, f"expected exactly 1 exclusion window after add, got {len(after_add)}: {after_add!r}"
    stored_window = after_add[0]
    assert stored_window["Reason"] == "sim2real-maintenance-window", (
        f"expected Reason='sim2real-maintenance-window', got {stored_window['Reason']!r}"
    )
    assert stored_window["Window"]["Duration"] == 2, (
        f"expected Window.Duration=2, got {stored_window['Window']['Duration']!r}"
    )
    assert stored_window["Window"]["DurationUnit"] == "HOUR", (
        f"expected Window.DurationUnit='HOUR', got {stored_window['Window']['DurationUnit']!r}"
    )
    assert stored_window["StartTime"] == start_time, (
        f"expected StartTime to round-trip as {start_time!r}, got {stored_window['StartTime']!r}"
    )

    remove_resp = sig.batch_update_exclusion_windows(
        SloIds=[arn],
        RemoveExclusionWindows=[
            {
                "Window": {"DurationUnit": "HOUR", "Duration": 2},
                "StartTime": start_time,
                "Reason": "sim2real-maintenance-window",
            }
        ],
    )
    assert remove_resp["Errors"] == [], f"expected RemoveExclusionWindows to succeed, got errors {remove_resp['Errors']!r}"

    after_remove = _poll_until(
        lambda: sig.list_service_level_objective_exclusion_windows(Id=arn)["ExclusionWindows"],
        lambda windows: windows == [],
        timeout_s=60,
        interval_s=3,
    )
    assert after_remove == [], f"expected the removed exclusion window to disappear, still present: {after_remove!r}"


def _poll_until(fetch, predicate, timeout_s=60, interval_s=3):
    import time

    deadline = time.monotonic() + timeout_s
    result = fetch()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"poll timed out after {timeout_s}s, last value={result!r}")
        time.sleep(interval_s)
        result = fetch()
    return result


def _delete_slo_ignore_missing(sig, arn: str) -> None:
    try:
        sig.delete_service_level_objective(Id=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _request_based_sli_config(namespace: str, metric_name: str) -> dict:
    return {
        "RequestBasedSliMetricConfig": {
            "TotalRequestCountMetric": [
                {
                    "Id": "total",
                    "MetricStat": {
                        "Metric": {
                            "Namespace": namespace,
                            "MetricName": metric_name,
                            "Dimensions": [],
                        },
                        "Period": 300,
                        "Stat": "Sum",
                    },
                    "ReturnData": True,
                }
            ],
            "MonitoredRequestCountMetric": {
                "BadCountMetric": [
                    {
                        "Id": "bad",
                        "MetricStat": {
                            "Metric": {
                                "Namespace": namespace,
                                "MetricName": f"{metric_name}Errors",
                                "Dimensions": [],
                            },
                            "Period": 300,
                            "Stat": "Sum",
                        },
                        "ReturnData": True,
                    }
                ]
            },
        }
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
