"""bedrock-model-invocation-logging-with-a-cross-region-bucket-rejected."""
from __future__ import annotations

import gzip
import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bedrock-model-invocation-logging-with-a-cross-region-bucket-rejected"
GROUP = 'errors'
SERVICES = ['bedrock']

MODEL_ID = "amazon.nova-lite-v1:0"

_PREFIX = "sim2real"
_PERMISSION_PROBE = "amazon-bedrock-logs-permission-check"
_DELIVERY_TIMEOUT_S = 240
# The refused bucket differs from the accepted one only in its region; asserted != ctx.region.
_OTHER_REGION = "us-east-2"


def _wide_open_policy(bucket):
    """Deliberately unconditioned Bedrock write policy, identical on both buckets.

    Bedrock's refusal message blames the bucket policy; holding it constant rules that out.
    """
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AmazonBedrockModelInvocationLogsWrite",
            "Effect": "Allow",
            "Principal": {"Service": "bedrock.amazonaws.com"},
            "Action": ["s3:PutObject", "s3:GetBucketAcl", "s3:ListBucket"],
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        }],
    })


def _empty_and_delete(s3, bucket):
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objects = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                       for o in (page.get("Versions") or [])
                       + (page.get("DeleteMarkers") or [])]
            if objects:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    s3.delete_bucket(Bucket=bucket)


def _make_bucket(ctx, region, scenario):
    s3 = ctx.client("s3", region=region)
    bucket = ctx.unique_name("sim2real-bedrock-invlog-")
    create_kwargs = {"Bucket": bucket}
    if region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": scenario}]})
    s3.put_bucket_policy(Bucket=bucket, Policy=_wide_open_policy(bucket))
    return s3, bucket


def _restore_logging(bc, prior):
    if prior is None:
        bc.delete_model_invocation_logging_configuration()
    else:
        bc.put_model_invocation_logging_configuration(loggingConfig=prior)


def _logging_config(bucket):
    return {
        "s3Config": {"bucketName": bucket, "keyPrefix": _PREFIX},
        "textDataDeliveryEnabled": True,
        "imageDataDeliveryEnabled": False,
        "embeddingDataDeliveryEnabled": False,
    }


class _UnexpectedSuccess(AssertionError):
    """Raised when a call this check requires to be refused instead succeeds."""


def _error(fn):
    """The exact AWS error code and message; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise _UnexpectedSuccess(
        f"the call was expected to be refused but returned {result!r}"
    )


def _records(s3, bucket):
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=_PREFIX):
        keys += [o["Key"] for o in page.get("Contents") or []]
    out = []
    for key in [k for k in keys if _PERMISSION_PROBE not in k]:
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        if key.endswith(".gz"):
            body = gzip.decompress(body)
        for line in body.decode("utf-8").splitlines():
            if line.strip():
                out.append(json.loads(line))
    return out


@tags("axis:rejection", "concern:negative-classes", "plane:control", "cap:c3", "resource:account-singleton:bedrock-invocation-logging")
def run(ctx) -> None:
    """Logging to a cross-region bucket is refused with ValidationException and its exact message,
    while the accepted same-region configuration stays unchanged and still delivers records.

    Reference: https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html
    """
    bc = ctx.client("bedrock")
    rt = ctx.client("bedrock-runtime")
    assert _OTHER_REGION != ctx.region, (
        f"the cross-region bucket must not be in the suite's own region {ctx.region!r}"
    )

    try:
        prior = bc.get_model_invocation_logging_configuration().get("loggingConfig")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise
        prior = None
    ctx.on_cleanup(lambda: _restore_logging(bc, prior))

    s3_local, local_bucket = _make_bucket(ctx, ctx.region, "bedrock-invlog-same-region")
    _, remote_bucket = _make_bucket(ctx, _OTHER_REGION, "bedrock-invlog-cross-region")

    bc.put_model_invocation_logging_configuration(loggingConfig=_logging_config(local_bucket))
    baseline = bc.get_model_invocation_logging_configuration()["loggingConfig"]
    assert baseline["s3Config"]["bucketName"] == local_bucket, (
        f"the same-region bucket must be accepted and reflected by Get; got {baseline!r}"
    )

    code, message = _error(lambda: bc.put_model_invocation_logging_configuration(
        loggingConfig=_logging_config(remote_bucket)))
    assert code == "ValidationException", (
        f"a log bucket in {_OTHER_REGION} must be refused with ValidationException; got "
        f"{code!r}: {message!r}"
    )
    # The message names the refused bucket, not the region mismatch.
    expected_message = (
        f"Failed to validate permissions for bucket: {remote_bucket}. "
        "Verify the S3 bucket policy is correct."
    )
    assert message == expected_message, (
        f"the refusal must name the bucket it refused: expected {expected_message!r}; got {message!r}"
    )

    after = bc.get_model_invocation_logging_configuration()["loggingConfig"]
    assert after == baseline, (
        f"the refused Put must leave the configuration byte-identical; before {baseline!r} "
        f"after {after!r}"
    )

    # A refusal that silently disabled logging would pass every assertion above.
    nonce = "sim2realnonce" + uuid.uuid4().hex[:12]
    response = rt.converse(
        modelId=MODEL_ID,
        messages=[{"role": "user", "content": [{
            "text": f"Repeat exactly this token and nothing else: {nonce}"}]}],
        inferenceConfig={"maxTokens": 40, "temperature": 0.0},
    )
    assert response["stopReason"] == "end_turn", (
        f"the post-refusal inference must succeed normally; got {response['stopReason']!r}"
    )

    deadline = time.monotonic() + _DELIVERY_TIMEOUT_S
    matched, seen = None, 0
    while True:
        delivered = _records(s3_local, local_bucket)
        seen = len(delivered)
        for record in delivered:
            if nonce in json.dumps(record.get("input", {})):
                matched = record
                break
        if matched is not None or time.monotonic() >= deadline:
            break
        time.sleep(2)
    assert matched is not None, (
        f"logging to the accepted same-region bucket must still work after the refusal; no "
        f"record carrying {nonce!r} appeared in s3://{local_bucket}/{_PREFIX} within "
        f"{_DELIVERY_TIMEOUT_S}s ({seen} record(s) delivered)"
    )
    assert matched["modelId"] == MODEL_ID, (
        f"the surviving configuration must log this model's invocations; got {matched!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
