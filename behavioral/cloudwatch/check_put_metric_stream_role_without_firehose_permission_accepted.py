"""put-metric-stream-role-without-firehose-permission-accepted."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "put-metric-stream-role-without-firehose-permission-accepted"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutMetricStream accepts a role with no Firehose permission and a nonexistent FirehoseArn.

    The stream reaches 'running'; AWS surfaces permission problems later as PublishErrorRate.
    """
    cw = ctx.client("cloudwatch")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-behav-mstream-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "streams.metrics.cloudwatch.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=_TAGS,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    # Deliberately no attached/inline policy: this role cannot call
    # firehose:PutRecord or firehose:PutRecordBatch on anything.

    stream_name = ctx.unique_name("sim2real-behav-mstream-")
    firehose_arn = (
        f"arn:aws:firehose:{ctx.region}:{account_id}:deliverystream/"
        f"{ctx.unique_name('sim2real-behav-nonexistent-fh-')}"
    )

    stream_arn = _put_metric_stream_with_retry(cw, stream_name, firehose_arn, role_arn)
    ctx.on_cleanup(lambda: cw.delete_metric_stream(Name=stream_name))
    assert stream_name in stream_arn and "metric-stream" in stream_arn, (
        f"expected the returned Arn to embed {stream_name!r} and 'metric-stream', got {stream_arn!r}"
    )

    described = cw.get_metric_stream(Name=stream_name)
    assert described["RoleArn"] == role_arn, (
        f"expected RoleArn {role_arn!r} echoed back, got {described['RoleArn']!r}"
    )
    assert described["FirehoseArn"] == firehose_arn, (
        f"expected FirehoseArn {firehose_arn!r} echoed back despite it not "
        f"corresponding to a real delivery stream, got {described['FirehoseArn']!r}"
    )
    assert described["State"] == "running", (
        f"expected the stream to reach 'running' despite RoleArn {role_arn!r} "
        f"granting no firehose:PutRecord permission, got {described['State']!r}"
    )


_TAGS = [
    {"Key": "sim2real", "Value": "put-metric-stream-role-without-firehose-permission"},
    {"Key": "sim2real:managed", "Value": "true"},
]


def _put_metric_stream_with_retry(cw, name: str, firehose_arn: str, role_arn: str, timeout_s: float = 30.0) -> str:
    """PutMetricStream, tolerating only IAM role-visibility eventual
    consistency; any other failure is the behavior under test and must
    propagate to the caller."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return cw.put_metric_stream(
                Name=name,
                FirehoseArn=firehose_arn,
                RoleArn=role_arn,
                OutputFormat="json",
                Tags=_TAGS,
            )["Arn"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidParameterValue":
                raise
            last_err = err
            time.sleep(2)
    raise AssertionError(f"PutMetricStream never succeeded: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
