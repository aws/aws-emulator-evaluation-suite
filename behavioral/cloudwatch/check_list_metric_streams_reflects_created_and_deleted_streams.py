"""list-metric-streams-reflects-created-and-deleted-streams."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-metric-streams-reflects-created-and-deleted-streams"
GROUP = "data-plane"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListMetricStreams includes a newly-created stream and excludes it right after deletion."""
    cw = ctx.client("cloudwatch")
    prereqs = _create_metric_stream_prereqs(ctx)

    name = ctx.unique_name("sim2real-cwms-list-")
    _retry_on(
        ctx,
        lambda: cw.put_metric_stream(
            Name=name,
            FirehoseArn=prereqs["firehose_arn"],
            RoleArn=prereqs["role_arn"],
            OutputFormat="json",
            Tags=[{"Key": "sim2real", "Value": "audit"}],
        ),
        ("InvalidParameterValueException", "AccessDeniedException"),
        "PutMetricStream never succeeded against a valid role/firehose",
        timeout_s=40.0,
    )
    ctx.on_cleanup(lambda: _delete_metric_stream_ignore_missing(cw, name))

    present = _list_all_stream_names(cw)
    assert name in present, f"newly created metric stream {name!r} missing from ListMetricStreams"

    cw.delete_metric_stream(Name=name)
    remaining = _poll_stream_absence(cw, name)
    assert name not in remaining, f"deleted metric stream {name!r} still present in ListMetricStreams"


# ===== helpers =====
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
        Tags=[{"Key": "sim2real", "Value": "audit"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_name, role_arn


def _attach_inline_policy(ctx, role_name, policy_name, statements):
    iam = ctx.client("iam")
    doc = {"Version": "2012-10-17", "Statement": statements}
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))


def _create_metric_stream_prereqs(ctx):
    """Provision a real S3 bucket + Firehose delivery stream + two IAM roles so the metric
    stream under test is wired to genuine infrastructure end-to-end."""
    s3 = ctx.client("s3")
    firehose = ctx.client("firehose")
    bucket_name = ctx.unique_name("sim2real-cwms-").lower().replace("_", "-")
    # us-east-1 is the one region CreateBucket rejects an explicit LocationConstraint for.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "audit"}]})

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
    # A newly created role is not yet assumable by Firehose: retry its propagation errors.
    fh_arn = _retry_on(
        ctx,
        lambda: firehose.create_delivery_stream(
            DeliveryStreamName=stream_name,
            DeliveryStreamType="DirectPut",
            S3DestinationConfiguration={"RoleARN": fh_role_arn, "BucketARN": f"arn:aws:s3:::{bucket_name}"},
            Tags=[{"Key": "sim2real", "Value": "audit"}],
        ),
        ("InvalidArgumentException", "AccessDeniedException"),
        "could not create prerequisite firehose delivery stream",
        timeout_s=75.0,
    )["DeliveryStreamARN"]
    ctx.on_cleanup(lambda: _delete_delivery_stream_and_wait(firehose, stream_name))

    deadline = time.monotonic() + 180
    status = None
    while time.monotonic() < deadline:
        status = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)["DeliveryStreamDescription"][
            "DeliveryStreamStatus"
        ]
        if status == "ACTIVE":
            break
        time.sleep(2)
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


def _retry_on(ctx, fn, codes, what, timeout_s):
    """Call fn() until it succeeds, retrying only `codes` (IAM propagation) every 2 s to the deadline."""
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    while True:
        try:
            return fn()
        except ClientError as e:
            if e.response["Error"]["Code"] not in codes:
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"{what}: {e}") from e
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
    """DeleteMetricStream of an already-deleted name succeeds, so any error is a real failure."""
    cw.delete_metric_stream(Name=name)


def _list_all_stream_names(cw):
    names = set()
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = cw.list_metric_streams(**kwargs)
        names.update(e["Name"] for e in resp.get("Entries", []))
        token = resp.get("NextToken")
        if not token:
            break
    return names


def _poll_stream_absence(cw, name, timeout_s=30, interval_s=3):
    deadline = time.monotonic() + timeout_s
    names = _list_all_stream_names(cw)
    while name in names and time.monotonic() < deadline:
        time.sleep(interval_s)
        names = _list_all_stream_names(cw)
    return names


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
