"""start-metric-streams-invalid-name-rejects-entire-batch."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-metric-streams-invalid-name-rejects-entire-batch"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartMetricStreams/StopMetricStreams on a batch of one real and one nonexistent name succeed:
    the real stream changes state and the unknown name is ignored, never created.
    """
    cw = ctx.client("cloudwatch")
    prereqs = _create_metric_stream_prereqs(ctx)

    name = ctx.unique_name("sim2real-cwms-batch-")
    _put_metric_stream_with_retry(
        ctx,
        cw,
        Name=name,
        FirehoseArn=prereqs["firehose_arn"],
        RoleArn=prereqs["role_arn"],
        OutputFormat="json",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_metric_stream_ignore_missing(cw, name))

    # New streams start running; stop it for a distinguishable baseline.
    cw.stop_metric_streams(Names=[name])
    _poll_stream_state(cw, name, "stopped")

    bogus_name = ctx.unique_name("sim2real-cwms-nonexistent-")
    # The docs' "all or nothing" rule covers permission failures, not nonexistent names.
    cw.start_metric_streams(Names=[name, bogus_name])
    _poll_stream_state(cw, name, "running")

    bogus_code, bogus_message = _client_error(lambda: cw.get_metric_stream(Name=bogus_name))
    assert bogus_code == "ResourceNotFoundException", (
        f"nonexistent stream name {bogus_name!r} unexpectedly has state "
        f"(GetMetricStream gave {bogus_code!r}: {bogus_message!r})"
    )
    assert bogus_message == "", bogus_message

    cw.stop_metric_streams(Names=[name, bogus_name])
    _poll_stream_state(cw, name, "stopped")


def _client_error(fn):
    """Call fn(); return (Error.Code, Error.Message) of its refusal, raising if fn succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a refusal but the call succeeded: {result!r}")


def _create_iam_role(ctx, name_prefix, principal):
    iam = ctx.client("iam")
    role_name = ctx.unique_name(name_prefix)
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_name, role_arn


def _attach_inline_policy(ctx, role_name, policy_name, statements):
    iam = ctx.client("iam")
    doc = {"Version": "2012-10-17", "Statement": statements}
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))


def _create_metric_stream_prereqs(ctx):
    """Provision a real S3 bucket, Firehose delivery stream and IAM roles for a metric stream."""
    s3 = ctx.client("s3")
    firehose = ctx.client("firehose")
    bucket_name = ctx.unique_name("sim2real-cwms-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _cleanup_bucket():
        objs = s3.list_objects_v2(Bucket=bucket_name).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket_name)

    ctx.on_cleanup(_cleanup_bucket)

    fh_role_name, fh_role_arn = _create_iam_role(ctx, "sim2real-cwms-fhrole-", "firehose.amazonaws.com")
    _attach_inline_policy(
        ctx,
        fh_role_name,
        "s3-write",
        [
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:GetBucketLocation", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
            }
        ],
    )

    stream_name = ctx.unique_name("sim2real-cwms-fhstream-")
    # A newly created role is not yet assumable everywhere.
    resp = _retry_propagation(
        ctx,
        lambda: firehose.create_delivery_stream(
            DeliveryStreamName=stream_name,
            DeliveryStreamType="DirectPut",
            S3DestinationConfiguration={"RoleARN": fh_role_arn, "BucketARN": f"arn:aws:s3:::{bucket_name}"},
            Tags=[{"Key": "sim2real:managed", "Value": "true"}],
        ),
        ("InvalidArgumentException", "AccessDeniedException"),
        "creating the prerequisite firehose delivery stream",
        timeout_s=75.0,
    )
    fh_arn = resp["DeliveryStreamARN"]
    ctx.on_cleanup(lambda: _delete_delivery_stream_and_wait(firehose, stream_name))

    deadline = time.monotonic() + 180
    status = None
    while time.monotonic() < deadline:
        status = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)["DeliveryStreamDescription"][
            "DeliveryStreamStatus"
        ]
        if status == "ACTIVE":
            break
        time.sleep(5)
    if status != "ACTIVE":
        raise AssertionError(f"firehose delivery stream never became ACTIVE (last status {status})")

    ms_role_name, ms_role_arn = _create_iam_role(
        ctx, "sim2real-cwms-msrole-", "streams.metrics.cloudwatch.amazonaws.com"
    )
    _attach_inline_policy(
        ctx,
        ms_role_name,
        "firehose-put",
        [{"Effect": "Allow", "Action": ["firehose:PutRecord", "firehose:PutRecordBatch"], "Resource": fh_arn}],
    )
    return {"firehose_arn": fh_arn, "role_arn": ms_role_arn}


def _put_metric_stream_with_retry(ctx, cw, **kwargs):
    # The metric-stream role's trust/permissions can take a few seconds to propagate.
    return _retry_propagation(
        ctx,
        lambda: cw.put_metric_stream(**kwargs),
        ("InvalidParameterValueException", "AccessDeniedException"),
        "PutMetricStream against a valid role/firehose",
        timeout_s=40.0,
    )


def _retry_propagation(ctx, fn, codes, what: str, timeout_s: float):
    """Call fn(), retrying every 2 s while it raises one of the IAM propagation *codes*."""
    from botocore.exceptions import ClientError

    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    while True:
        try:
            return fn()
        except ClientError as e:
            if e.response["Error"]["Code"] not in codes:
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"{what} did not succeed within {timeout_s}s: {e}") from e
        time.sleep(2)


def _delete_delivery_stream_and_wait(firehose, name, timeout_s=300.0):
    """Delete the delivery stream and poll until it is gone: it keeps listing while DELETING."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            firehose.delete_delivery_stream(DeliveryStreamName=name)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    while time.monotonic() < deadline:
        try:
            firehose.describe_delivery_stream(DeliveryStreamName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(2)
    raise AssertionError(f"firehose delivery stream {name!r} still exists {timeout_s:.0f}s after DeleteDeliveryStream")


def _delete_metric_stream_ignore_missing(cw, name):
    from botocore.exceptions import ClientError

    try:
        cw.delete_metric_stream(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_stream_state(cw, name, expected_state, timeout_s=60, interval_s=3):
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = cw.get_metric_stream(Name=name)["State"]
        if state == expected_state:
            return
        time.sleep(interval_s)
    raise AssertionError(f"metric stream {name!r} never reached state {expected_state!r} (last seen {state!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
