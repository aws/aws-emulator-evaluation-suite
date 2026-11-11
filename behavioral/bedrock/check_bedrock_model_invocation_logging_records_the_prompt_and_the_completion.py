"""bedrock-model-invocation-logging-records-the-prompt-and-the-completion."""
from __future__ import annotations

import gzip
import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bedrock-model-invocation-logging-records-the-prompt-and-the-completion"
GROUP = 'observability'
SERVICES = ['bedrock']

MODEL_ID = "amazon.nova-lite-v1:0"

_PREFIX = "sim2real"
# Bedrock writes two zero-byte probe objects named `amazon-bedrock-logs-permission-check` when the
# configuration is accepted. They are not invocation records and polling must not stop on them.
_PERMISSION_PROBE = "amazon-bedrock-logs-permission-check"
_DELIVERY_TIMEOUT_S = 240


def _bucket_policy(bucket, account, region):
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AmazonBedrockModelInvocationLogsWrite",
            "Effect": "Allow",
            "Principal": {"Service": "bedrock.amazonaws.com"},
            "Action": ["s3:PutObject"],
            "Resource": [f"arn:aws:s3:::{bucket}/*"],
            "Condition": {
                "StringEquals": {"aws:SourceAccount": account},
                "ArnLike": {"aws:SourceArn": f"arn:aws:bedrock:{region}:{account}:*"},
            },
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


def _restore_logging(bc, prior):
    """Put back the account-level singleton exactly as it was found."""
    if prior is None:
        bc.delete_model_invocation_logging_configuration()
    else:
        bc.put_model_invocation_logging_configuration(loggingConfig=prior)


def _record_keys(s3, bucket):
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=_PREFIX):
        keys += [o["Key"] for o in page.get("Contents") or []]
    return [k for k in keys if _PERMISSION_PROBE not in k]


def _read_records(s3, bucket, keys):
    out = []
    for key in keys:
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        if key.endswith(".gz"):
            body = gzip.decompress(body)
        for line in body.decode("utf-8").splitlines():
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c3", "resource:account-singleton:bedrock-invocation-logging")
def run(ctx) -> None:
    """Model invocation logging writes the real prompt and completion into S3, with token
    counts equal to the usage the Converse response reported, and logs no text that was never
    sent."""
    bc = ctx.client("bedrock")
    s3 = ctx.client("s3")
    account = ctx.client("sts").get_caller_identity()["Account"]
    rt = ctx.client("bedrock-runtime")

    # ACCOUNT-and-region-level singleton state: stash it first and restore it in cleanup, before
    # anything else can fail.
    try:
        prior = bc.get_model_invocation_logging_configuration().get("loggingConfig")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise
        prior = None
    ctx.on_cleanup(lambda: _restore_logging(bc, prior))

    bucket = ctx.unique_name("sim2real-bedrock-invlog-")
    create_kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "bedrock-invocation-logging"}]})
    s3.put_bucket_policy(Bucket=bucket,
                        Policy=_bucket_policy(bucket, account, ctx.region))

    bc.put_model_invocation_logging_configuration(loggingConfig={
        "s3Config": {"bucketName": bucket, "keyPrefix": _PREFIX},
        "textDataDeliveryEnabled": True,
        "imageDataDeliveryEnabled": False,
        "embeddingDataDeliveryEnabled": False,
    })
    live = bc.get_model_invocation_logging_configuration()["loggingConfig"]
    assert live["s3Config"]["bucketName"] == bucket, (
        f"the configuration must name the bucket just created; got {live!r}"
    )
    assert live["textDataDeliveryEnabled"] is True, (
        f"text delivery must be enabled for this check to mean anything; got {live!r}"
    )

    nonce = "sim2realnonce" + uuid.uuid4().hex[:12]
    control_nonce = "sim2realnonce" + uuid.uuid4().hex[:12]
    response = rt.converse(
        modelId=MODEL_ID,
        messages=[{"role": "user", "content": [{
            "text": f"Repeat exactly this token and nothing else: {nonce}"}]}],
        inferenceConfig={"maxTokens": 40, "temperature": 0.0},
    )
    completion = "".join(b.get("text", "") for b in response["output"]["message"]["content"])
    assert completion.strip(), f"the inference produced no text to look for; {response!r}"

    # Bounded poll for the record carrying THIS nonce -- not merely for "some object", because
    # Bedrock's own permission-probe objects and any other invocation's record land in the same
    # prefix.
    deadline = time.monotonic() + _DELIVERY_TIMEOUT_S
    matched, seen = None, 0
    while True:
        records = _read_records(s3, bucket, _record_keys(s3, bucket))
        seen = len(records)
        for record in records:
            if nonce in json.dumps(record.get("input", {})):
                matched = record
                break
        if matched is not None or time.monotonic() >= deadline:
            break
        time.sleep(2)

    assert matched is not None, (
        f"no invocation log record carrying the prompt nonce {nonce!r} appeared within "
        f"{_DELIVERY_TIMEOUT_S}s; {seen} record(s) were delivered to s3://{bucket}/{_PREFIX}"
    )

    prompt_text = matched["input"]["inputBodyJson"]["messages"][0]["content"][0]["text"]
    assert nonce in prompt_text, (
        f"the record's logged prompt must contain the nonce verbatim; got {prompt_text!r}"
    )
    logged_output = matched["output"]["outputBodyJson"]["output"]["message"]["content"]
    logged_completion = "".join(b.get("text", "") for b in logged_output)
    assert logged_completion == completion, (
        f"the record's logged completion must be the text the API returned; logged "
        f"{logged_completion!r} returned {completion!r}"
    )
    assert matched["modelId"] == MODEL_ID, (
        f"the record must name the model invoked; got {matched['modelId']!r}"
    )
    assert matched["operation"] == "Converse", (
        f"the record must name the operation; got {matched['operation']!r}"
    )
    assert matched["input"]["inputTokenCount"] == response["usage"]["inputTokens"], (
        f"the record's inputTokenCount must equal the usage the API reported inline; record "
        f"{matched['input']['inputTokenCount']!r} api {response['usage']!r}"
    )
    assert matched["output"]["outputTokenCount"] == response["usage"]["outputTokens"], (
        f"the record's outputTokenCount must equal the usage the API reported inline; record "
        f"{matched['output']['outputTokenCount']!r} api {response['usage']!r}"
    )

    # Effect absent: a nonce that was never sent appears in no record. An emulator that logs the
    # request it was handed rather than the one that ran cannot be caught by the positive half.
    everything = json.dumps(_read_records(s3, bucket, _record_keys(s3, bucket)))
    assert control_nonce not in everything, (
        f"the control nonce {control_nonce!r} was never sent to Bedrock yet appears in a "
        f"delivered log record"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
