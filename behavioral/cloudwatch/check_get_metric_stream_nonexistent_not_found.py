"""get-metric-stream-nonexistent-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-metric-stream-nonexistent-not-found"
GROUP = 'metric-streams'
SERVICES = ['cloudwatch']

def _err(fn):
    """Call fn(); return the botocore error (Code, Message). A SUCCESS raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetMetricStream on a name that was never created reports ResourceNotFoundException with an empty
    message and the name is absent from ListMetricStreams, while a stream the check created reads back
    as running and is listed, so the check tells "unknown name" apart from "every name rejected"."""
    cw = ctx.client("cloudwatch")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region

    real_name = ctx.unique_name("sim2real-behav-cwprobe-real-")
    firehose_arn = (
        f"arn:aws:firehose:{region}:{account_id}:deliverystream/"
        f"{ctx.unique_name('sim2real-behav-cwprobe-fh-')}"
    )
    role_arn = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-behav-cwprobe-role-')}"
    cw.put_metric_stream(Name=real_name, FirehoseArn=firehose_arn, RoleArn=role_arn, OutputFormat="json")
    ctx.on_cleanup(lambda: cw.delete_metric_stream(Name=real_name))

    # Positive control: the account and this operation are otherwise healthy.
    state = cw.get_metric_stream(Name=real_name)["State"]
    assert state == "running", f"positive control: newly created metric stream should be running, got {state!r}"

    missing_name = ctx.unique_name("sim2real-behav-cwprobe-missing-")

    def get_op():
        return cw.get_metric_stream(Name=missing_name)

    code, message = _err(get_op)
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for an unknown metric stream, got {code}"
    )
    # AWS returns this code with no message text.
    assert message == "", f"expected an empty message, got {message!r}"

    # The unknown stream must be absent from the listing, and the real one present.
    listed = {e["Name"] for e in cw.list_metric_streams(MaxResults=500).get("Entries", [])}
    assert missing_name not in listed, "unknown metric stream appeared in ListMetricStreams"
    assert real_name in listed, "real metric stream missing from ListMetricStreams"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
