"""tag-list-untag-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "tag-list-untag-lifecycle"
GROUP = 'tags'
SERVICES = ['cloudwatch']

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource/ListTagsForResource/UntagResource form a consistent lifecycle on an alarm ARN."""
    cw = ctx.client("cloudwatch")
    _acct = ctx.client("sts").get_caller_identity()["Account"]
    alarm_name = ctx.unique_name("sim2real-behav-cwprobe-alarm-")
    namespace = ctx.unique_name("sim2real-behav-cwprobe-ns-")
    ctx.on_cleanup(lambda _n=alarm_name: cw.delete_alarms(AlarmNames=[_n]))

    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=namespace,
        MetricName="Manual",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
    )
    arn = f"arn:aws:cloudwatch:{ctx.region}:{_acct}:alarm:{alarm_name}"

    cw.tag_resource(ResourceARN=arn, Tags=[{"Key": "env", "Value": "test"}])

    def probe():
        return cw.list_tags_for_resource(ResourceARN=arn)

    resp = _poll_until(probe, lambda r: len(r.get("Tags", [])) > 0, timeout_s=20, interval_s=2)
    tags = {t["Key"]: t["Value"] for t in resp["Tags"]}
    assert tags == {"env": "test"}, f"expected exactly the applied tag, got {tags}"

    cw.untag_resource(ResourceARN=arn, TagKeys=["env"])

    resp2 = _poll_until(probe, lambda r: len(r.get("Tags", [])) == 0, timeout_s=20, interval_s=2)
    assert resp2["Tags"] == [], f"expected no tags after untag, got {resp2['Tags']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
