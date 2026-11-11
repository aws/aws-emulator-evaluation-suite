"""concurrent-put-alarm-mute-rule-overwrite-last-writer-wins."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-put-alarm-mute-rule-overwrite-last-writer-wins"
GROUP = "concurrency"
SERVICES = ["cloudwatch"]

_TAGS = [{"Key": "sim2real:managed", "Value": "true"}]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent PutAlarmMuteRule calls on one rule name, each with its own
    Description and Schedule Duration, leave exactly one writer's (Description,
    Duration) pair, and a repeated read returns the same pair."""
    cw = ctx.client("cloudwatch")
    ns = ctx.unique_name("sim2real-cw-race-mute-ns-")
    alarm_name = ctx.unique_name("sim2real-cw-race-mute-alarm-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=ns,
        MetricName="RaceMuteMetric",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="notBreaching",
        Tags=_TAGS,
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    rule_name = ctx.unique_name("sim2real-cw-race-mute-rule-")
    writers = [(f"race-writer-{i}", f"PT{30 + i}M") for i in range(8)]

    def _put(desc, duration):
        cw.put_alarm_mute_rule(
            Name=rule_name,
            Description=desc,
            Rule={"Schedule": {"Expression": "cron(0 3 * * *)", "Duration": duration}},
            MuteTargets={"AlarmNames": [alarm_name]},
            Tags=_TAGS,
        )

    with ThreadPoolExecutor(max_workers=len(writers)) as ex:
        futures = [ex.submit(_put, desc, duration) for desc, duration in writers]
        for f in futures:
            f.result()
    ctx.on_cleanup(lambda: cw.delete_alarm_mute_rule(AlarmMuteRuleName=rule_name))

    final = cw.get_alarm_mute_rule(AlarmMuteRuleName=rule_name)
    final_pair = (final["Description"], final["Rule"]["Schedule"]["Duration"])
    assert final_pair in writers, (
        f"final (Description, Duration) {final_pair!r} does not match any single "
        f"writer's pair out of {writers!r} -- a value was stitched together from two "
        f"different concurrent writes"
    )

    again = cw.get_alarm_mute_rule(AlarmMuteRuleName=rule_name)
    again_pair = (again["Description"], again["Rule"]["Schedule"]["Duration"])
    assert again_pair == final_pair, (
        f"repeated reads disagree: {final_pair!r} vs {again_pair!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
