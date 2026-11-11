"""start-metric-streams-nonexistent-stream-name-silently-ignored."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "start-metric-streams-nonexistent-stream-name-silently-ignored"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartMetricStreams naming one stopped stream and one that does not exist succeeds, starts
    the real stream and does not make the missing name appear in ListMetricStreams: the API's
    all-or-nothing rule covers permission failures, not existence."""
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

    cw.put_metric_stream(
        Name=name,
        FirehoseArn=firehose_arn,
        RoleArn=role_arn,
        OutputFormat="json",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_metric_stream(Name=name))
    cw.stop_metric_streams(Names=[name])
    _poll_until(
        lambda: cw.get_metric_stream(Name=name)["State"], lambda s: s == "stopped"
    )

    bogus_name = ctx.unique_name("sim2real-nonexistent-stream-")
    # The mixed batch is accepted: a refusal raises ClientError and fails the check.
    cw.start_metric_streams(Names=[name, bogus_name])

    # the real, existing stream WAS started despite the bogus name in the same request
    _poll_until(
        lambda: cw.get_metric_stream(Name=name)["State"], lambda s: s == "running"
    )

    # effect absent: the nonexistent name was not fabricated into a real stream
    listed_names = {e["Name"] for e in cw.list_metric_streams()["Entries"]}
    assert bogus_name not in listed_names, (
        f"expected {bogus_name!r} to remain absent from ListMetricStreams, "
        f"but it was found in {listed_names!r}"
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
