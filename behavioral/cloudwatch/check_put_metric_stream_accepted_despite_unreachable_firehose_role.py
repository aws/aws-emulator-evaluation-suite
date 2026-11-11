"""put-metric-stream-accepted-despite-unreachable-firehose-role."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "put-metric-stream-accepted-despite-unreachable-firehose-role"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutMetricStream accepts a RoleArn/FirehoseArn pair that does not exist and the stream
    reads back running, then stops and starts normally: CloudWatch validates the destination
    only at delivery time (surfaced through PublishErrorRate), not at creation."""
    cw = ctx.client("cloudwatch")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region
    name = ctx.unique_name("sim2real-mstream-")
    firehose_arn = (
        f"arn:aws:firehose:{region}:{account_id}:deliverystream/"
        f"{ctx.unique_name('sim2real-nonexistent-')}"
    )
    role_arn = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-nonexistent-')}"

    resp = cw.put_metric_stream(
        Name=name,
        FirehoseArn=firehose_arn,
        RoleArn=role_arn,
        OutputFormat="json",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: cw.delete_metric_stream(Name=name))
    assert resp["Arn"], (
        f"PutMetricStream with a nonexistent RoleArn={role_arn!r} and "
        f"FirehoseArn={firehose_arn!r} did not return a stream Arn: {resp!r}"
    )

    desc = cw.get_metric_stream(Name=name)
    assert desc["State"] == "running", (
        f"expected State='running' immediately after PutMetricStream with an "
        f"unreachable role/firehose, got {desc['State']!r}"
    )

    cw.stop_metric_streams(Names=[name])
    _poll_until(
        lambda: cw.get_metric_stream(Name=name)["State"], lambda s: s == "stopped"
    )

    cw.start_metric_streams(Names=[name])
    _poll_until(
        lambda: cw.get_metric_stream(Name=name)["State"], lambda s: s == "running"
    )


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"condition not met within {timeout_s}s, last value: {value!r}"
            )
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
