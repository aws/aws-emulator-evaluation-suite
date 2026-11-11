"""metric-stream-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "metric-stream-lifecycle"
GROUP = 'metric-streams'
SERVICES = ['cloudwatch']

def _err(fn):
    """Call fn(); return the botocore error (Code, Message). An unexpected SUCCESS raises,
    because an emulator accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")

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

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutMetricStream (fabricated Firehose and role ARNs, which are resolved only at delivery) creates a
    listed stream in state running; StopMetricStreams and StartMetricStreams move it to stopped and back
    to running; after DeleteMetricStream, GetMetricStream raises ResourceNotFoundException and the listing omits it."""
    cw = ctx.client("cloudwatch")
    account = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-behav-cwprobe-stream-")
    firehose_arn = f"arn:aws:firehose:{ctx.region}:{account}:deliverystream/{name}"
    role_arn = f"arn:aws:iam::{account}:role/{name}"
    ctx.on_cleanup(lambda _n=name: cw.delete_metric_stream(Name=_n))
    cw.put_metric_stream(
        Name=name,
        FirehoseArn=firehose_arn,
        RoleArn=role_arn,
        OutputFormat="json",
        Tags=[{"Key": "sim2real-owner", "Value": "metric-stream-lifecycle"}],
    )

    def probe_state():
        return cw.get_metric_stream(Name=name)["State"]

    state = _poll_until(probe_state, lambda s: s == "running", timeout_s=30, interval_s=3)
    assert state == "running", f"expected new metric stream to start running, got {state}"

    listing = cw.list_metric_streams()
    names = {e["Name"] for e in listing.get("Entries", [])}
    assert name in names, f"expected {name} in ListMetricStreams output"

    cw.stop_metric_streams(Names=[name])
    state2 = _poll_until(probe_state, lambda s: s == "stopped", timeout_s=30, interval_s=3)
    assert state2 == "stopped", f"expected stopped after StopMetricStreams, got {state2}"

    cw.start_metric_streams(Names=[name])
    state3 = _poll_until(probe_state, lambda s: s == "running", timeout_s=30, interval_s=3)
    assert state3 == "running", f"expected running after StartMetricStreams, got {state3}"

    cw.delete_metric_stream(Name=name)

    # Overly-permissive check: a deleted metric stream must genuinely 404, not
    # be silently retained by an emulator that no-ops DeleteMetricStream.
    error = _err(lambda: cw.get_metric_stream(Name=name))
    assert error == ("ResourceNotFoundException", ""), (
        f"expected the ResourceNotFoundException for a deleted stream, got {error!r}"
    )

    listing2 = cw.list_metric_streams()
    names2 = {e["Name"] for e in listing2.get("Entries", [])}
    assert name not in names2, f"deleted stream {name} should not appear in ListMetricStreams"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
