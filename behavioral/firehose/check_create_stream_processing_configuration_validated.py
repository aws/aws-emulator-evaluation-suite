"""create-stream-processing-configuration-validated."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-stream-processing-configuration-validated"
GROUP = 'overly-permissive'
SERVICES = ['firehose']

# ===== helpers =====
# The helpers follow three rules:
#   1. teardown POLLS TO A DELETABLE STATE, then deletes, then polls to actual
#      disappearance, and raises on a deadline miss.
#   2. the bucket teardown handles versions, delete-markers and in-flight multipart
#      uploads and RETRIES, because Firehose may have written objects into the bucket
#      and a non-empty bucket CANNOT be deleted.
#   3. no `except Exception: pass` anywhere on the assertion path.

TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "firehose.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}

# Kinesis read actions are included so the same delivery-role policy also works
# for KinesisStreamAsSource streams; the role is created and deleted per check.
ACCESS_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:AbortMultipartUpload",
                "s3:GetBucketLocation",
                "s3:GetObject",
                "s3:ListBucket",
                "s3:ListBucketMultipartUploads",
                "s3:PutObject",
                "kms:Decrypt",
                "kms:GenerateDataKey",
                "logs:PutLogEvents",
                "kinesis:DescribeStream",
                "kinesis:GetShardIterator",
                "kinesis:GetRecords",
                "kinesis:ListShards",
            ],
            "Resource": "*",
        }
    ],
}


def _err(fn):
    """Call fn(); return (Error.Code, Error.Message) on ClientError; a success fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"the call succeeded where a ClientError was expected: {result!r}")


def _poll(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    """Poll probe() until predicate(result); return the result. Never a bare sleep."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not reached within {timeout_s}s; last observed {last!r}"
            )
        time.sleep(interval_s)


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _managed_tags_kv():
    return [
        {"Key": "sim2real:managed", "Value": "true"},
        {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
    ]


def _bucket_arn(bucket):
    return f"arn:aws:s3:::{bucket}"


def _describe(ctx, name):
    return ctx.client("firehose").describe_delivery_stream(DeliveryStreamName=name)[
        "DeliveryStreamDescription"
    ]


def _status(ctx, name):
    """Current DeliveryStreamStatus, or None once the stream has actually vanished."""
    try:
        return _describe(ctx, name)["DeliveryStreamStatus"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return None
        raise


def _bucket_exists(ctx, bucket):
    try:
        ctx.client("s3").head_bucket(Bucket=bucket)
        return True
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") in ("404", "NoSuchBucket"):
            return False
        raise


def _empty_bucket(ctx, bucket):
    """Remove every object, version, delete-marker and in-flight multipart upload.
    Firehose may have written into this bucket, and a bucket that still holds an
    object cannot be deleted -- so this must run to completion before delete_bucket."""
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            batch = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in list(page.get("Versions", [])) + list(page.get("DeleteMarkers", []))
            ]
            if batch:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": batch})
    except ClientError:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            batch = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if batch:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": batch})
    for page in s3.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
        for up in page.get("Uploads", []):
            s3.abort_multipart_upload(
                Bucket=bucket, Key=up["Key"], UploadId=up["UploadId"]
            )


def _make_bucket(ctx):
    """Create the S3 delivery bucket; register a teardown that empties it, deletes it,
    and polls until it is gone. A leaked bucket holding Firehose output bills for
    storage indefinitely, so the teardown retries and raises on a deadline miss."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-fh-dst-")
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _managed_tags_kv()})

    def _teardown():
        deadline = time.monotonic() + 180
        while True:
            try:
                _empty_bucket(ctx, bucket)
                s3.delete_bucket(Bucket=bucket)
                break
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code in ("NoSuchBucket", "404"):
                    return
                if time.monotonic() >= deadline:
                    raise AssertionError(
                        f"LEAK: bucket {bucket} not deleted within 180s (last error {code})"
                    )
                time.sleep(5)
        _poll(
            lambda: _bucket_exists(ctx, bucket),
            lambda exists: exists is False,
            timeout_s=60,
            interval_s=3,
            description=f"bucket {bucket} disappearance",
        )

    ctx.on_cleanup(_teardown)
    return bucket


def _delivery_role_arn(ctx):
    """A real IAM role Firehose can assume -- Firehose validates the role at
    CreateDeliveryStream time, so a fabricated ARN is not usable."""
    iam = ctx.client("iam")
    role = ctx.unique_name("sim2real-behav-fh-role-")
    resp = iam.create_role(
        RoleName=role,
        AssumeRolePolicyDocument=json.dumps(TRUST_POLICY),
        Description="SimParity firehose behavioral check role",
        Tags=_managed_tags_kv(),
    )
    iam.put_role_policy(
        RoleName=role,
        PolicyName="firehose-destination-access",
        PolicyDocument=json.dumps(ACCESS_POLICY),
    )

    def _teardown():
        try:
            for pn in iam.list_role_policies(RoleName=role).get("PolicyNames", []):
                iam.delete_role_policy(RoleName=role, PolicyName=pn)
            iam.delete_role(RoleName=role)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise

    ctx.on_cleanup(_teardown)
    return resp["Role"]["Arn"]


def _delete_stream_and_wait(ctx, name, *, timeout_s=420):
    """Poll to a deletable state, delete, then poll to ACTUAL disappearance.
    delete_delivery_stream returns while the stream is still DELETING, and it is
    refused outright while the stream is CREATING -- a fire-and-forget delete
    therefore silently leaks the stream."""
    fh = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    while True:
        state = _status(ctx, name)
        if state is None:
            return
        if state != "DELETING":
            try:
                fh.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code == "ResourceNotFoundException":
                    return
                if code != "ResourceInUseException":
                    raise
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"LEAK: delivery stream {name} still {state} after {timeout_s}s"
            )
        time.sleep(5)


def _create_stream(ctx, name, **kwargs):
    """CreateDeliveryStream with teardown registered AT CREATION TIME, retrying while
    a brand-new IAM role is still propagating (Firehose rejects an unassumable role
    with InvalidArgumentException on the first try) -- bounded poll, never a sleep."""
    fh = ctx.client("firehose")
    deadline = time.monotonic() + 150
    while True:
        try:
            resp = fh.create_delivery_stream(DeliveryStreamName=name, **kwargs)
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            msg = (err.get("Message") or "").lower()
            propagating = err.get("Code") == "InvalidArgumentException" and (
                "assume" in msg or "not authorized" in msg or "does not exist" in msg
            )
            if propagating and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise
    ctx.on_cleanup(lambda: _delete_stream_and_wait(ctx, name))
    return resp


def _s3_dest(role_arn, bucket, **overrides):
    cfg = {
        "RoleARN": role_arn,
        "BucketARN": _bucket_arn(bucket),
        "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
    }
    cfg.update(overrides)
    return cfg


def _wait_active(ctx, name, *, timeout_s=420):
    return _poll(
        lambda: _status(ctx, name),
        lambda s: s == "ACTIVE",
        timeout_s=timeout_s,
        interval_s=5,
        description=f"delivery stream {name} ACTIVE",
    )


def _active_stream(ctx, prefix, *, bucket=None, role_arn=None, **dest_overrides):
    """An ACTIVE DirectPut -> ExtendedS3 stream plus the bucket and role it needs.
    Bucket and role are created (and their teardowns registered) BEFORE the stream,
    so the LIFO cleanup order is stream -> role -> bucket: reverse-dependency."""
    if bucket is None:
        bucket = _make_bucket(ctx)
    if role_arn is None:
        role_arn = _delivery_role_arn(ctx)
    name = ctx.unique_name(prefix)
    _create_stream(
        ctx,
        name,
        ExtendedS3DestinationConfiguration=_s3_dest(role_arn, bucket, **dest_overrides),
    )
    _wait_active(ctx, name)
    return name, bucket, role_arn


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDeliveryStream validates ProcessingConfiguration synchronously: a Lambda
    processor with no LambdaArn parameter and an unknown ProcessorType are both refused,
    neither creates a stream, and the same request without the processor is accepted."""
    fh = ctx.client("firehose")
    bucket = _make_bucket(ctx)
    role_arn = _delivery_role_arn(ctx)

    def _create(processing, name):
        return fh.create_delivery_stream(
            DeliveryStreamName=name,
            ExtendedS3DestinationConfiguration={
                "RoleARN": role_arn,
                "BucketARN": _bucket_arn(bucket),
                "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
                "ProcessingConfiguration": processing,
            },
        )

    # Leg 1 -- break exactly one thing: a Lambda processor with no LambdaArn parameter.
    n1 = ctx.unique_name("sim2real-behav-fh-noarn-proc-")
    code1, msg1 = _err(
        lambda: _create(
            {"Enabled": True, "Processors": [{"Type": "Lambda"}]},
            n1,
        )
    )
    assert code1 == "InvalidArgumentException", (
        "a Lambda processor with no LambdaArn parameter must be refused with "
        f"InvalidArgumentException, got {code1!r}: {msg1!r}"
    )
    assert msg1 == "LambdaArn is required when Lambda processor is used.", (
        f"expected the exact InvalidArgumentException message AWS returns, got {msg1!r}"
    )
    assert _status(ctx, n1) is None, f"the rejected create must not have created {n1}"

    # Leg 2 -- break exactly one thing: a ProcessorType outside the modeled enum.
    n2 = ctx.unique_name("sim2real-behav-fh-badproc-")
    code2, msg2 = _err(
        lambda: _create(
            {
                "Enabled": True,
                "Processors": [
                    {
                        "Type": "NotAProcessor",
                        "Parameters": [
                            {"ParameterName": "LambdaArn", "ParameterValue": "x"}
                        ],
                    }
                ],
            },
            n2,
        )
    )
    # MEASURED on real AWS: an out-of-enum ProcessorType is caught by the server-side
    # GENERIC request validator, so it is ValidationException -- a DIFFERENT layer from
    # leg 1's InvalidArgumentException, which is Firehose's own semantic verdict on a
    # well-typed request. Asserting both codes is what pins the two layers apart; an
    # emulator that funnels every bad ProcessingConfiguration into one code fails here.
    assert code2 == "ValidationException", (
        "an unknown ProcessorType violates the modeled enum and must be refused by the "
        "generic request validator with ValidationException, NOT with Firehose's own "
        f"InvalidArgumentException (that is leg 1's code), got {code2!r}: {msg2!r}"
    )
    assert msg2 == "1 validation error detected: Value at 'extendedS3DestinationConfiguration.processingConfiguration.processors.1.member.type' failed to satisfy constraint: Member must satisfy enum value set: [Decompression, Lambda, RecordDeAggregation, MetadataExtraction, AppendDelimiterToRecord, CloudWatchLogProcessing]", (
        f"expected the exact ValidationException message AWS returns, got {msg2!r}"
    )
    assert code1 != code2, (
        f"a missing required parameter and an out-of-enum type are refused by different "
        f"validation layers and must not share a code; both returned {code1!r}"
    )
    assert (
        "processingConfiguration.processors" in msg2
        and "member.type' failed to satisfy constraint: Member must satisfy enum value set"
        in msg2
    ), (
        "the refusal must name the offending member path inside the processors list and "
        f"say it failed the enum value set, got {msg2!r}"
    )
    assert _status(ctx, n2) is None, f"the rejected create must not have created {n2}"

    # Control: the identical create with processing explicitly disabled is accepted, so
    # the processor -- not the rest of the destination config -- caused both refusals.
    n3 = ctx.unique_name("sim2real-behav-fh-noproc-")
    _create_stream(
        ctx,
        n3,
        ExtendedS3DestinationConfiguration=_s3_dest(
            role_arn, bucket, ProcessingConfiguration={"Enabled": False, "Processors": []}
        ),
        Tags=_managed_tags_kv(),
    )
    _wait_active(ctx, n3)
    ext = _describe(ctx, n3)["Destinations"][0]["ExtendedS3DestinationDescription"]
    assert ext["ProcessingConfiguration"]["Enabled"] is False, (
        f"the accepted create must echo the disabled ProcessingConfiguration, got "
        f"{ext.get('ProcessingConfiguration')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
