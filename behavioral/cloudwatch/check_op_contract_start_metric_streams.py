"""op-contract-startMetricStreams."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-startMetricStreams"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartMetricStreams moves a stopped stream to running; a batch containing one valid
    name plus one nonexistent name is accepted (200) and still starts the valid stream --
    unknown names are silently ignored rather than causing the whole batch to be rejected."""
    cw = ctx.client("cloudwatch")
    infra = _provision_metric_stream_infra(ctx)
    stream_name = ctx.unique_name("sim2real-cwms-start-")
    _put_metric_stream_with_retry(
        ctx,
        Name=stream_name,
        FirehoseArn=infra["firehose_arn"],
        RoleArn=infra["role_arn"],
        OutputFormat="json",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_metric_stream(Name=stream_name))

    # a newly created stream starts running by default; stop it so Start has an observable transition
    cw.stop_metric_streams(Names=[stream_name])
    _wait_metric_stream_state(ctx, stream_name, "stopped")

    cw.start_metric_streams(Names=[stream_name])
    state = _wait_metric_stream_state(ctx, stream_name, "running")
    assert state == "running", f"expected 'running' after StartMetricStreams, got {state!r}"

    # a batch containing one valid name plus one nonexistent name is NOT rejected on real
    # AWS: unknown names are silently ignored, and the valid name in the same batch is
    # still acted on (there is no "all-or-nothing" semantics for StartMetricStreams).
    cw.stop_metric_streams(Names=[stream_name])
    _wait_metric_stream_state(ctx, stream_name, "stopped")
    bogus_name = ctx.unique_name("sim2real-cwms-missing-")
    resp = cw.start_metric_streams(Names=[stream_name, bogus_name])
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected a mixed valid/bogus batch to be accepted, got {resp['ResponseMetadata']['HTTPStatusCode']}"
    )
    state = _wait_metric_stream_state(ctx, stream_name, "running")
    assert state == "running", "the valid stream in a mixed valid/bogus batch must still be started"

    # effect absent: the nonexistent name must not have been materialized as a stream as
    # a side effect of appearing in the batch -- an independent read, at a different
    # operation than the one that mutated, is the terminal assertion.
    bogus_code, bogus_message = _error(lambda: cw.get_metric_stream(Name=bogus_name))
    assert bogus_code == "ResourceNotFoundException", (
        f"the nonexistent name from the batch must not exist as a stream, got {bogus_code!r}"
    )
    # real AWS sends this refusal with an empty message
    assert bogus_message == "", f"expected an empty refusal message, got {bogus_message!r}"


def _provision_metric_stream_infra(ctx) -> dict:
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    firehose = ctx.client("firehose")

    bucket = ctx.unique_name("sim2real-cwms-start-b-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))

    fh_role_name = ctx.unique_name("sim2real-cwms-start-fhrole-")
    fh_role = iam.create_role(
        RoleName=fh_role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "firehose.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=fh_role_name))
    iam.put_role_policy(
        RoleName=fh_role_name,
        PolicyName="s3-write",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:PutObject", "s3:GetBucketLocation", "s3:ListBucket"],
                        "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=fh_role_name, PolicyName="s3-write"))

    stream_name = ctx.unique_name("sim2real-cwms-start-fh-")
    deadline = time.monotonic() + 90
    last_exc = None
    created = False
    while time.monotonic() < deadline:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=stream_name,
                DeliveryStreamType="DirectPut",
                S3DestinationConfiguration={
                    "RoleARN": fh_role["Arn"],
                    "BucketARN": f"arn:aws:s3:::{bucket}",
                },
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
            created = True
            break
        except Exception as exc:  # noqa: BLE001 - IAM propagation retry
            last_exc = exc
            time.sleep(5)
    if not created:
        raise AssertionError(f"could not create delivery stream: {last_exc}")
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=stream_name))
    firehose_arn = _wait_firehose_active(ctx, stream_name)

    cw_role_name = ctx.unique_name("sim2real-cwms-start-cwrole-")
    cw_role = iam.create_role(
        RoleName=cw_role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "streams.metrics.cloudwatch.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=cw_role_name))
    iam.put_role_policy(
        RoleName=cw_role_name,
        PolicyName="firehose-write",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["firehose:PutRecord", "firehose:PutRecordBatch"],
                        "Resource": firehose_arn,
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=cw_role_name, PolicyName="firehose-write"))

    return {"firehose_arn": firehose_arn, "role_arn": cw_role["Arn"]}


def _wait_firehose_active(ctx, stream_name, timeout_s=120.0) -> str:
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)[
            "DeliveryStreamDescription"
        ]
        if desc["DeliveryStreamStatus"] == "ACTIVE":
            return desc["DeliveryStreamARN"]
        time.sleep(3)
    raise AssertionError(f"delivery stream {stream_name} never became ACTIVE")


def _empty_and_delete_bucket(ctx, bucket) -> None:
    s3 = ctx.client("s3")
    try:
        resp = s3.list_objects_v2(Bucket=bucket)
        objects = resp.get("Contents", [])
        if objects:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objects]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    s3.delete_bucket(Bucket=bucket)


def _put_metric_stream_with_retry(ctx, *, timeout_s=90.0, **kwargs):
    cw = ctx.client("cloudwatch")
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return cw.put_metric_stream(**kwargs)
        except Exception as exc:  # noqa: BLE001 - IAM/role trust propagation retry
            last_exc = exc
            time.sleep(5)
    raise AssertionError(f"put_metric_stream never succeeded: {last_exc}")


def _wait_metric_stream_state(ctx, name, desired_state, timeout_s=60.0) -> str:
    cw = ctx.client("cloudwatch")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = cw.get_metric_stream(Name=name)["State"]
        if state == desired_state:
            return state
        time.sleep(3)
    raise AssertionError(f"metric stream {name} never reached state {desired_state} (last={state})")


def _error(fn):
    """Return (code, message) of the ClientError fn raises. A SUCCESS is an AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
