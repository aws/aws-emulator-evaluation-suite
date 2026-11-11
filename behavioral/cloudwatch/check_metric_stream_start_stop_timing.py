"""metric-stream-start-stop-timing."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "metric-stream-start-stop-timing"
GROUP = 'metric-streams'
SERVICES = ['cloudwatch']


def _err(fn):
    """Call fn(); return the botocore error (Code, Message). A SUCCESS raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


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


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StopMetricStreams and StartMetricStreams move a stream to stopped and back to running, each advancing
    LastUpdateDate; a 300-character name is rejected by both with the exact ValidationError, and stopping
    a nonexistent name succeeds without creating a stream (GetMetricStream: ResourceNotFoundException)."""
    cw = ctx.client("cloudwatch")
    account = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-behav-cwprobe-mstream-")
    firehose_arn = f"arn:aws:firehose:{ctx.region}:{account}:deliverystream/{name}"
    role_arn = f"arn:aws:iam::{account}:role/{name}"
    ctx.on_cleanup(lambda _n=name: cw.delete_metric_stream(Name=_n))

    cw.put_metric_stream(Name=name, FirehoseArn=firehose_arn, RoleArn=role_arn, OutputFormat="json")

    def get():
        return cw.get_metric_stream(Name=name)

    stream = _poll_until(get, lambda s: s.get("State") is not None, timeout_s=30, interval_s=2, description="stream visible")
    assert stream["State"] == "running", f"expected new metric stream to start running, got {stream['State']}"
    t_created = stream["LastUpdateDate"]

    cw.stop_metric_streams(Names=[name])
    stream = _poll_until(
        get, lambda s: s["State"] == "stopped", timeout_s=30, interval_s=2, description="stream stopped"
    )
    t_stopped = stream["LastUpdateDate"]
    # STRICT advance: a >= comparison is satisfied by an emulator that returns a constant,
    # never-updated LastUpdateDate, which is exactly the divergence this check exists to catch.
    # The poll between transitions guarantees seconds of separation, so > is not tight.
    assert t_stopped > t_created, (
        f"expected LastUpdateDate to advance when the stream transitions to stopped, "
        f"got {t_stopped} vs {t_created}"
    )

    cw.start_metric_streams(Names=[name])
    stream = _poll_until(
        get, lambda s: s["State"] == "running", timeout_s=30, interval_s=2, description="stream running again"
    )
    t_started = stream["LastUpdateDate"]
    assert t_started > t_stopped, (
        f"expected LastUpdateDate to advance again once restarted, got {t_started} vs {t_stopped}"
    )

    # A stream name over the documented 255-character maximum is rejected, not truncated;
    # a well-formed nonexistent name is a no-op, checked below.
    too_long_name = "x" * 300
    too_long_message = (
        f"1 validation error detected: Value '[{too_long_name}]' at 'names' failed to satisfy "
        f"constraint: Member must satisfy constraint: [Member must have length less than or equal "
        f"to 255, Member must have length greater than or equal to 1]"
    )
    stop_error = _err(lambda: cw.stop_metric_streams(Names=[too_long_name]))
    assert stop_error == ("ValidationError", too_long_message), (
        f"expected the ValidationError for a stream name exceeding 255 characters, got {stop_error!r}"
    )
    start_error = _err(lambda: cw.start_metric_streams(Names=[too_long_name]))
    assert start_error == ("ValidationError", too_long_message), (
        f"expected the ValidationError for a stream name exceeding 255 characters, got {start_error!r}"
    )

    missing = ctx.unique_name("sim2real-behav-cwprobe-mstream-missing-")
    missing_resp = cw.stop_metric_streams(Names=[missing])
    assert missing_resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        "empirically, StopMetricStreams on a syntactically valid but nonexistent stream "
        "name succeeds (permissive no-op) rather than raising -- asserted here so a "
        "fidelity check catches an emulator that instead raises for this case"
    )
    # Independent read at the destination: the no-op call must not have fabricated a
    # stream entry for the name it was given.
    missing_error = _err(lambda: cw.get_metric_stream(Name=missing))
    assert missing_error == ("ResourceNotFoundException", ""), (
        f"expected the no-op StopMetricStreams call not to fabricate a stream, "
        f"got GetMetricStream error {missing_error!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
