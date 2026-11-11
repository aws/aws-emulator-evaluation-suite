"""put-metric-stream-conflicting-filters-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-metric-stream-conflicting-filters-rejected"
GROUP = 'overly-permissive'
SERVICES = ['cloudwatch']

def _err(fn):
    """Call fn(); return the botocore Error dict if a ClientError is raised. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutMetricStream rejects specifying both IncludeFilters and ExcludeFilters (overly-permissive check)."""
    cw = ctx.client("cloudwatch")
    _acct = ctx.client("sts").get_caller_identity()["Account"]
    control_name = ctx.unique_name("sim2real-behav-cwprobe-ctrl-")
    stream_name = ctx.unique_name("sim2real-behav-cwprobe-stream-")
    firehose_arn = f"arn:aws:firehose:{ctx.region}:{_acct}:deliverystream/{stream_name}"
    role_arn = f"arn:aws:iam::{_acct}:role/{stream_name}"

    # Positive control: the identical fabricated FirehoseArn/RoleArn pair is accepted when only one
    # filter kind is given -- PutMetricStream does not validate the destination synchronously, so
    # this proves the account/wiring can create a stream at all. Without it, a rejection below would
    # be indistinguishable from "this account can't call PutMetricStream at all".
    cw.put_metric_stream(
        Name=control_name,
        FirehoseArn=firehose_arn,
        RoleArn=role_arn,
        OutputFormat="json",
        IncludeFilters=[{"Namespace": "AWS/EC2"}],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_metric_stream(Name=control_name))
    control_arn = cw.get_metric_stream(Name=control_name).get("Arn")
    assert control_arn, f"positive control PutMetricStream did not create a readable stream, got Arn={control_arn!r}"

    def op():
        resp = cw.put_metric_stream(
            Name=stream_name,
            FirehoseArn=firehose_arn,
            RoleArn=role_arn,
            OutputFormat="json",
            IncludeFilters=[{"Namespace": "AWS/EC2"}],
            ExcludeFilters=[{"Namespace": "AWS/S3"}],
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )
        # Only reached if the target wrongly accepted the conflicting combination.
        ctx.on_cleanup(lambda: cw.delete_metric_stream(Name=stream_name))
        return resp

    err = _err(op)
    assert err["Code"] == "InvalidParameterCombination", (
        f"expected InvalidParameterCombination for IncludeFilters+ExcludeFilters, got {err!r}"
    )
    expected = "IncludeFilters and ExcludeFilters cannot both be present"
    assert err.get("Message", "") == expected, f"expected {expected!r}, got {err.get('Message', '')!r}"

    # Must not have been created despite the error.
    def get_op():
        return cw.get_metric_stream(Name=stream_name)

    get_err = _err(get_op)
    assert get_err["Code"] == "ResourceNotFoundException", (
        f"rejected PutMetricStream must not create the stream, got GetMetricStream error {get_err!r}"
    )
    expected = ""
    assert get_err.get("Message", "") == expected, f"expected {expected!r}, got {get_err.get('Message', '')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
