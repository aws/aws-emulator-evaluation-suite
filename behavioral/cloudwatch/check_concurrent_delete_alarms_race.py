"""concurrent-delete-alarms-race."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-delete-alarms-race"
GROUP = 'concurrency'
SERVICES = ['cloudwatch']

_METRIC_ALARM_DEFAULTS = dict(
    Namespace="AWS/EC2",
    MetricName="CPUUtilization",
    Statistic="Average",
    Period=60,
    EvaluationPeriods=1,
    Threshold=80.0,
    ComparisonOperator="GreaterThanThreshold",
)


def _run_concurrent(fns, *, timeout_s=60):
    import concurrent.futures
    results = [None] * len(fns)
    resolved = set()

    def _capture(fut, idx):
        try:
            results[idx] = fut.result()
        except Exception as exc:
            results[idx] = exc
        resolved.add(idx)
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns)))
    try:
        future_to_idx = {ex.submit(fn): i for i, fn in enumerate(fns)}
        try:
            for fut in concurrent.futures.as_completed(future_to_idx, timeout=timeout_s):
                _capture(fut, future_to_idx[fut])
        except concurrent.futures.TimeoutError as timeout_exc:
            for fut, idx in future_to_idx.items():
                if idx in resolved:
                    continue
                if fut.done():
                    _capture(fut, idx)
                else:
                    fut.cancel()
                    results[idx] = timeout_exc
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return results


def _concurrent_error_codes(results):
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get('Error', {}).get('Code'))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Six concurrent DeleteAlarms on one alarm all succeed while six concurrent DescribeAlarms each
    see it either whole (AlarmName, StateValue, AlarmArn) or absent, and the alarm is gone after."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-behav-cwprobe-alarm-delcc-")
    cw.put_metric_alarm(
        AlarmName=name,
        Tags=[{"Key": "sim2real-behav-check", "Value": "concurrent-delete-alarms-race"}],
        **_METRIC_ALARM_DEFAULTS,
    )
    ctx.on_cleanup(lambda _n=name: cw.delete_alarms(AlarmNames=[_n]))

    def describe():
        r = cw.describe_alarms(AlarmNames=[name])
        return r.get("MetricAlarms", [])

    def delete():
        cw.delete_alarms(AlarmNames=[name])
        return "deleted"

    tasks = [delete] * 6 + [describe] * 6
    results = _run_concurrent(tasks, timeout_s=60)
    delete_results = results[:6]
    describe_results = results[6:]

    delete_codes = _concurrent_error_codes(delete_results)
    assert not delete_codes, (
        f"DeleteAlarms racing on the same (idempotent) alarm name must never error, "
        f"got codes={delete_codes}"
    )

    for r in describe_results:
        assert not isinstance(r, BaseException), (
            f"DescribeAlarms must never raise while racing a concurrent delete, got {r!r}"
        )
        assert len(r) in (0, 1), (
            f"DescribeAlarms must never observe more than one record for a single alarm "
            f"name during a delete race, got {r}"
        )
        if len(r) == 1:
            alarm = r[0]
            assert alarm.get("AlarmName") == name, f"unexpected AlarmName in racing snapshot: {alarm}"
            assert "StateValue" in alarm and "AlarmArn" in alarm, (
                f"a half-deleted/corrupted alarm record must never be observed mid-race: {alarm}"
            )

    final = cw.describe_alarms(AlarmNames=[name]).get("MetricAlarms", [])
    assert final == [], f"expected the alarm to be fully deleted after the race settles, got {final}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
