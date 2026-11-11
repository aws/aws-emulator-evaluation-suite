"""metric-stream-conflicting-filters-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "metric-stream-conflicting-filters-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutMetricStream with both IncludeFilters and ExcludeFilters is rejected with
    InvalidParameterCombination "IncludeFilters and ExcludeFilters cannot both be present" and creates no
    stream (GetMetricStream: ResourceNotFoundException), while the same call with IncludeFilters alone succeeds."""
    cw = ctx.client("cloudwatch")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    control_name = ctx.unique_name("sim2real-mstream-control-")
    control_firehose_arn = (
        f"arn:aws:firehose:{ctx.region}:{account_id}:deliverystream/{control_name}-does-not-exist"
    )
    control_role_arn = f"arn:aws:iam::{account_id}:role/{control_name}-does-not-exist"
    control_resp = cw.put_metric_stream(
        Name=control_name,
        FirehoseArn=control_firehose_arn,
        RoleArn=control_role_arn,
        OutputFormat="json",
        IncludeFilters=[{"Namespace": "AWS/EC2"}],
    )
    ctx.on_cleanup(lambda: cw.delete_metric_stream(Name=control_name))
    assert control_resp["Arn"], "positive control: PutMetricStream with IncludeFilters alone must succeed"

    name = ctx.unique_name("sim2real-mstream-")
    firehose_arn = f"arn:aws:firehose:{ctx.region}:{account_id}:deliverystream/{name}-does-not-exist"
    role_arn = f"arn:aws:iam::{account_id}:role/{name}-does-not-exist"

    error = _client_error(
        lambda: cw.put_metric_stream(
            Name=name,
            FirehoseArn=firehose_arn,
            RoleArn=role_arn,
            OutputFormat="json",
            IncludeFilters=[{"Namespace": "AWS/EC2"}],
            ExcludeFilters=[{"Namespace": "AWS/ELB"}],
        )
    )
    assert (error.get("Code"), error.get("Message")) == ("InvalidParameterCombination", "IncludeFilters and ExcludeFilters cannot both be present"), (
        f"expected the InvalidParameterCombination rejection for IncludeFilters+ExcludeFilters together, got {error}"
    )

    not_found = _client_error(lambda: cw.get_metric_stream(Name=name))
    assert (not_found.get("Code"), not_found.get("Message")) == ("ResourceNotFoundException", ""), (
        f"rejected PutMetricStream must not create the stream, got GetMetricStream error {not_found}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. A SUCCESS raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
