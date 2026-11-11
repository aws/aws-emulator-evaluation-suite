"""anomaly-band-alarm-cites-band-high-recreates-its-deleted-detector-and-fires-out-of-band."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "anomaly-band-alarm-cites-band-high-recreates-its-deleted-detector-and-fires-out-of-band"
GROUP = "anomaly-detector"
SERVICES = ["cloudwatch"]

_BASELINE = (10.0, 10.5, 11.0)
_IN_BAND = 10.5
_OUT_OF_BAND = 5000.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Create_Anomaly_Detection_Alarm.html
@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api",
      "plane:data", "timing:real-time")
def run(ctx) -> None:
    """An ANOMALY_DETECTION_BAND alarm over a Maximum series is OK in-band citing the band's High,
    re-creates its deleted detector (an unreferenced one stays gone) while staying OK, then fires
    on an out-of-band value.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Create_Anomaly_Detection_Alarm.html
    """
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealBehavAdAlarm")
    alarm_name = ctx.unique_name("sim2real-behav-adalarm-")
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    value = [_IN_BAND]

    for metric in ("X", "Y"):
        points = [{"MetricName": metric, "Timestamp": now - timedelta(minutes=2 * i),
                   "Value": _BASELINE[i % 3]} for i in range(1, 91)]
        for j in range(0, len(points), 20):
            cw.put_metric_data(Namespace=namespace, MetricData=points[j:j + 20])

    def _det(metric: str) -> dict:
        return {"Namespace": namespace, "MetricName": metric, "Stat": "Maximum"}

    def _detectors() -> dict[str, str]:
        out, token = {}, None
        while True:
            page = cw.describe_anomaly_detectors(Namespace=namespace,
                                                 **({"NextToken": token} if token else {}))
            for d in page["AnomalyDetectors"]:
                out[d["SingleMetricAnomalyDetector"]["MetricName"]] = d["StateValue"]
            token = page.get("NextToken")
            if not token:
                return out

    metrics = [
        {"Id": "m1", "MetricStat": {"Metric": {"Namespace": namespace, "MetricName": "X"},
                                    "Period": 60, "Stat": "Maximum"}, "ReturnData": True},
        {"Id": "ad1", "Expression": "ANOMALY_DETECTION_BAND(m1, 2)", "ReturnData": True},
    ]

    def _band_at(ts: datetime) -> dict:
        """The band's {"Low": v, "High": v} at ts; a side is missing while GetMetricData serves no
        band value there yet."""
        res = cw.get_metric_data(MetricDataQueries=metrics, StartTime=ts,
                                 EndTime=ts + timedelta(seconds=60))
        got = {}
        for r in res["MetricDataResults"]:
            if r["Id"] == "ad1":
                hits = [v for t, v in zip(r["Timestamps"], r["Values"]) if t == ts]
                assert len(hits) <= 1, (
                    f"band series {r['Label']!r} has {len(hits)} values at {ts.isoformat()}"
                )
                if hits:
                    got[r["Label"].rsplit(" ", 1)[-1]] = float(hits[0])
        return got

    def _publish() -> None:
        cw.put_metric_data(Namespace=namespace, MetricData=[
            {"MetricName": "X", "Timestamp": datetime.now(timezone.utc), "Value": value[0]}])

    # Registered before the alarm's cleanup so (LIFO) the alarm is deleted first and cannot
    # re-create the detectors.
    for metric in ("X", "Y"):
        ctx.on_cleanup(lambda m=metric: _delete_detector_if_present(cw, SingleMetricAnomalyDetector=_det(m)))
        cw.put_anomaly_detector(SingleMetricAnomalyDetector=_det(metric))

    cw.put_metric_alarm(
        AlarmName=alarm_name,
        # ReturnData is omitted on the band, not set False: an explicit False makes AWS refuse the
        # alarm with ValidationError "Metrics list must contain exactly one metric matching the
        # ThresholdMetricId parameter".
        Metrics=[metrics[0], {"Id": "ad1", "Expression": metrics[1]["Expression"]}],
        ThresholdMetricId="ad1",
        ComparisonOperator="GreaterThanUpperThreshold",
        EvaluationPeriods=1,
        TreatMissingData="missing",
        ActionsEnabled=False,
        AlarmDescription="sim2real-behav: anomaly band alarm across a detector delete",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    # --- 1. in-band -> OK, and the cited threshold IS the band --------------------------------- #
    # The alarm stays INSUFFICIENT_DATA until the model behind its band is trained, and
    # GetMetricData can serve the band at the evaluated minute only some time after the alarm
    # first evaluates it; one deadline bounds both waits.
    phase1_deadline = time.monotonic() + 480.0
    ok = _poll_until(
        lambda: _describe(cw, alarm_name),
        lambda a: a["StateValue"] != "INSUFFICIENT_DATA",
        timeout_s=480.0, interval_s=10.0, on_iteration=_publish,
        description=f"alarm {alarm_name!r} evaluated the in-band value {_IN_BAND}",
    )
    assert ok["StateValue"] == "OK", (
        f"{_IN_BAND} sits inside the band trained on {_BASELINE}, so the alarm must be OK; it is "
        f"{ok['StateValue']!r}: {ok['StateReason']!r}"
    )
    srd = json.loads(ok["StateReasonData"])
    point = srd["evaluatedDatapoints"][0]
    ts = datetime.strptime(point["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z")
    band = _poll_until(
        lambda: _band_at(ts),
        lambda b: sorted(b) == ["High", "Low"],
        timeout_s=max(1.0, phase1_deadline - time.monotonic()), interval_s=10.0,
        on_iteration=_publish,
        description=f"GetMetricData serving both band values at the evaluated minute {ts.isoformat()}",
    )
    lo, hi = band["Low"], band["High"]
    assert float(point["value"]) == _IN_BAND, f"the OK verdict cites {point['value']!r}"
    assert lo <= _IN_BAND <= hi, f"GetMetricData's band at {ts.isoformat()} is [{lo}, {hi}]"
    cited_upper = float(point["threshold"])
    assert abs(cited_upper - hi) <= 1e-3 * max(1.0, abs(hi)), (
        f"the evaluator cites upper threshold {cited_upper!r} at {ts.isoformat()} but "
        f"GetMetricData's High there is {hi!r} -- the alarm is not thresholded by the band"
    )

    # --- 2. delete both detectors; only the alarm-referenced one comes back -------------------- #
    # A live alarm re-creates its deleted model; Y, referenced by no alarm, is the control.
    cw.delete_anomaly_detector(SingleMetricAnomalyDetector=_det("X"))
    cw.delete_anomaly_detector(SingleMetricAnomalyDetector=_det("Y"))
    gone = _detectors()
    assert "X" not in gone and "Y" not in gone, (
        f"DeleteAnomalyDetector returned but DescribeAnomalyDetectors still lists {gone!r}"
    )
    back = _poll_until(
        _detectors,
        lambda d: "X" in d,
        timeout_s=240.0, interval_s=10.0, on_iteration=_publish,
        description=(f"the live alarm {alarm_name!r} re-created the deleted detector on X (real "
                     f"AWS does, within ~1 min)"),
    )
    assert "Y" not in back, (
        f"detector Y, deleted with NO alarm referencing it, reappeared ({back!r}) by the time X "
        f"was re-created -- the re-creation must come from the alarm reference"
    )
    mid = _describe(cw, alarm_name)
    assert mid["StateValue"] == "OK", (
        f"after its detector was deleted and re-created, the alarm reports {mid['StateValue']!r} "
        f"({mid['StateReason']!r}); real AWS keeps it OK"
    )

    # --- 3. out-of-band -> ALARM on the re-created model --------------------------------------- #
    # The statistic is Maximum, so a period holding the out-of-band value cites exactly that value.
    value[0] = _OUT_OF_BAND
    _publish()
    fired = _poll_until(
        lambda: _describe(cw, alarm_name),
        lambda a: a["StateValue"] == "ALARM",
        timeout_s=300.0, interval_s=10.0, on_iteration=_publish,
        description=f"alarm {alarm_name!r} fired on {_OUT_OF_BAND}, far above the band",
    )
    fsrd = json.loads(fired["StateReasonData"])
    fpoint = fsrd["evaluatedDatapoints"][0]
    assert float(fpoint["value"]) == _OUT_OF_BAND, f"the ALARM verdict cites {fpoint['value']!r}"
    assert float(fpoint["value"]) > float(fpoint["threshold"]), (
        f"ALARM was reached with value {fpoint['value']!r} not above its cited upper threshold "
        f"{fpoint['threshold']!r}"
    )
    history = _poll_until(
        lambda: _state_updates(cw, alarm_name),
        lambda items: any(_new_state(i) == "ALARM" for i in items),
        timeout_s=120.0, interval_s=5.0,
        description=f"a StateUpdate history item for the ALARM of {alarm_name!r}",
    )
    states = [_new_state(i) for i in history]
    assert states.index("OK") < states.index("ALARM"), (
        f"history states in order are {states!r}; the in-band OK must precede the ALARM"
    )
    assert "Y" not in _detectors(), "detector Y came back although nothing references it"


def _describe(cw, alarm_name):
    for page in cw.get_paginator("describe_alarms").paginate(
            AlarmNames=[alarm_name], AlarmTypes=["MetricAlarm"]):
        for alarm in page.get("MetricAlarms", []):
            if alarm["AlarmName"] == alarm_name:
                return alarm
    raise AssertionError(f"alarm {alarm_name!r} is not present in DescribeAlarms")


def _state_updates(cw, alarm_name):
    items = []
    for page in cw.get_paginator("describe_alarm_history").paginate(
            AlarmName=alarm_name, HistoryItemType="StateUpdate", ScanBy="TimestampAscending"):
        items.extend(page.get("AlarmHistoryItems", []))
    return items


def _new_state(item) -> str:
    return json.loads(item["HistoryData"]).get("newState", {}).get("stateValue", "")


def _poll_until(probe, predicate, *, timeout_s, interval_s, description, on_iteration=None):
    """Poll probe() until predicate(result); AssertionError on exhaustion."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            last = probe()
        except ClientError as exc:
            last = exc.response["Error"]
        else:
            if predicate(last):
                return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} did not happen within {timeout_s}s; "
                                 f"last observation {last!r}")
        if on_iteration is not None:
            on_iteration()
        time.sleep(interval_s)


def _delete_detector_if_present(cw, **spec) -> None:
    """Teardown: delete the detector unless the body already deleted it; any other error raises."""
    try:
        cw.delete_anomaly_detector(**spec)
    except cw.exceptions.ResourceNotFoundException:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
