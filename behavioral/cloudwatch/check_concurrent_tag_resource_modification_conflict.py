"""concurrent-tag-resource-modification-conflict."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from behavioral_harness import tags

CHECK = "concurrent-tag-resource-modification-conflict"
GROUP = "concurrency"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Racing TagResource/UntagResource calls on one alarm ARN fail, if at all, only with
    ConcurrentModificationException, and leave at most one "race" tag, holding the seed value or one
    a writer set."""
    from botocore.exceptions import ClientError

    cw = ctx.client("cloudwatch")
    alarm_name = ctx.unique_name("sim2real-cw-tagrace-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace="AWS/EC2",
        MetricName="CPUUtilization",
        Statistic="Average",
        Period=300,
        EvaluationPeriods=1,
        Threshold=90.0,
        ComparisonOperator="GreaterThanThreshold",
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))
    alarm_arn = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["AlarmArn"]

    # Seed the contested key so both TagResource (overwrite) and UntagResource (remove) race
    # against a well-defined starting point.
    cw.tag_resource(ResourceARN=alarm_arn, Tags=[{"Key": "race", "Value": "seed"}])

    n = 16
    barrier = threading.Barrier(n)

    def racer(i: int) -> Optional[str]:
        barrier.wait()
        try:
            if i % 2 == 0:
                cw.tag_resource(ResourceARN=alarm_arn, Tags=[{"Key": "race", "Value": f"v{i}"}])
            else:
                cw.untag_resource(ResourceARN=alarm_arn, TagKeys=["race"])
            return None
        except ClientError as exc:
            return exc.response["Error"]["Code"]

    with ThreadPoolExecutor(max_workers=n) as pool:
        results = list(pool.map(racer, range(n)))

    error_codes = {c for c in results if c is not None}
    assert error_codes <= {"ConcurrentModificationException"}, (
        f"concurrent tag mutation on the same resource surfaced an unexpected error code: {error_codes}"
    )

    tags = cw.list_tags_for_resource(ResourceARN=alarm_arn)["Tags"]
    race_tags = [t for t in tags if t["Key"] == "race"]
    assert len(race_tags) <= 1, f"tag state corrupted by the race: found {len(race_tags)} 'race' entries: {race_tags}"
    if race_tags:
        allowed_values = {f"v{i}" for i in range(n) if i % 2 == 0} | {"seed"}
        assert race_tags[0]["Value"] in allowed_values, (
            f"final tag value {race_tags[0]['Value']!r} was never written by any racer"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
