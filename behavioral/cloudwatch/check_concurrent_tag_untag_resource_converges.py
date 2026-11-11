"""concurrent-tag-untag-resource-converges."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-tag-untag-resource-converges"
GROUP = "concurrency"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent TagResource and UntagResource calls on disjoint keys of one alarm ARN all succeed
    within a few ConcurrentModificationException retries, and afterward every added tag is present
    and every removed baseline tag is gone."""
    from botocore.exceptions import ClientError

    cw = ctx.client("cloudwatch")
    alarm_name = ctx.unique_name("sim2real-behav-tagalarm-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=ctx.unique_name("sim2real/behav/"),
        MetricName="ConcurrencyProbe",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))
    alarm_arn = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["AlarmArn"]

    def tag_call(cw_client, arn, key):
        for attempt in range(5):
            try:
                cw_client.tag_resource(ResourceARN=arn, Tags=[{"Key": key, "Value": "v"}])
                return ("ok", None)
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code == "ConcurrentModificationException" and attempt < 4:
                    time.sleep(0.5)
                    continue
                return ("err", code)

    def untag_call(cw_client, arn, key):
        for attempt in range(5):
            try:
                cw_client.untag_resource(ResourceARN=arn, TagKeys=[key])
                return ("ok", None)
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code == "ConcurrentModificationException" and attempt < 4:
                    time.sleep(0.5)
                    continue
                return ("err", code)

    new_keys = [f"sim2real-new-0-{i}" for i in range(4)]
    baseline_keys = [f"sim2real-base-0-{i}" for i in range(4)]
    cw.tag_resource(ResourceARN=alarm_arn, Tags=[{"Key": k, "Value": "v"} for k in baseline_keys])

    jobs = [(tag_call, k) for k in new_keys] + [(untag_call, k) for k in baseline_keys]
    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = [ex.submit(fn, cw, alarm_arn, key) for fn, key in jobs]
        results = [f.result() for f in futures]

    for (_fn, key), (status, code) in zip(jobs, results):
        assert status == "ok", (
            f"concurrent tag/untag for {key!r} never succeeded even after bounded retries "
            f"on ConcurrentModificationException; last error: {code}"
        )

    # No lost updates: every concurrent tag/untag writer's intended effect must be reflected
    # afterward; a transient ConcurrentModificationException is absorbed by the bounded retries
    # above, so the final state must be fully consistent.
    tags_after = {t["Key"]: t["Value"] for t in cw.list_tags_for_resource(ResourceARN=alarm_arn)["Tags"]}
    for key in new_keys:
        assert key in tags_after, f"concurrent tag_resource for {key!r} was silently lost"
    for key in baseline_keys:
        assert key not in tags_after, f"concurrent untag_resource for {key!r} was silently lost"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
