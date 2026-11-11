"""tag-resource-concurrent-modification-converges."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-concurrent-modification-converges"
GROUP = "concurrency"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent TagResource and UntagResource calls on one alarm fail only with
    ConcurrentModificationException, and the final tags reflect exactly the racers that reported
    success: no successful write lost, no failed write applied."""
    cw = ctx.client("cloudwatch")
    alarm_name = ctx.unique_name("sim2real-tagcc-alarm-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace="Sim2Real/Behavioral",
        MetricName="TagConcurrencyMetric",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))
    alarm_arn = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["AlarmArn"]

    # Baseline tags established sequentially (no race on setup), so the concurrent
    # phase below can race UntagResource against a well-known starting set.
    baseline_keys = [f"keep{i}" for i in range(5)]
    cw.tag_resource(ResourceARN=alarm_arn, Tags=[{"Key": k, "Value": "v"} for k in baseline_keys])

    add_keys = [f"added{i}" for i in range(5)]

    def _add_racer(key: str) -> dict[str, Any]:
        try:
            cw.tag_resource(ResourceARN=alarm_arn, Tags=[{"Key": key, "Value": "v"}])
            return {"op": "add", "key": key, "ok": True, "code": None}
        except ClientError as exc:
            return {"op": "add", "key": key, "ok": False, "code": exc.response["Error"]["Code"]}

    def _remove_racer(key: str) -> dict[str, Any]:
        try:
            cw.untag_resource(ResourceARN=alarm_arn, TagKeys=[key])
            return {"op": "remove", "key": key, "ok": True, "code": None}
        except ClientError as exc:
            return {"op": "remove", "key": key, "ok": False, "code": exc.response["Error"]["Code"]}

    tasks = [(_add_racer, k) for k in add_keys] + [(_remove_racer, k) for k in baseline_keys]
    with ThreadPoolExecutor(max_workers=len(tasks)) as pool:
        futures = [pool.submit(fn, key) for fn, key in tasks]
        results = [f.result() for f in futures]

    unexpected = [r for r in results if not r["ok"] and r["code"] != "ConcurrentModificationException"]
    assert not unexpected, f"racer(s) failed with an unexpected (non-Concurrent) error: {unexpected}"

    final_tags = {t["Key"]: t["Value"] for t in cw.list_tags_for_resource(ResourceARN=alarm_arn)["Tags"]}

    for r in results:
        if r["op"] == "add":
            if r["ok"]:
                assert r["key"] in final_tags, f"successful add of {r['key']!r} was lost: {final_tags}"
            else:
                assert r["key"] not in final_tags, f"failed add of {r['key']!r} was silently applied: {final_tags}"
        else:  # remove
            if r["ok"]:
                assert r["key"] not in final_tags, f"successful removal of {r['key']!r} was not applied: {final_tags}"
            else:
                assert r["key"] in final_tags, f"failed removal of {r['key']!r} was silently applied: {final_tags}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
