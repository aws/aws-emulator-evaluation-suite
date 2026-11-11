"""model-invocation-logging-text-delivery-disabled-omits-bodies."""
from __future__ import annotations

import gzip
import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "model-invocation-logging-text-delivery-disabled-omits-bodies"
GROUP = "observability"
SERVICES = ["bedrock"]

MODEL_ID = "amazon.nova-lite-v1:0"

_PREFIX = "sim2real"
# Bedrock writes zero-byte objects named `amazon-bedrock-logs-permission-check` when a configuration
# is accepted. They are not invocation records and polling must not stop on them.
_PERMISSION_PROBE = "amazon-bedrock-logs-permission-check"
_DELIVERY_TIMEOUT_S = 110.0


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
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        objects = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                   for o in (page.get("Versions") or []) + (page.get("DeleteMarkers") or [])]
        if objects:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _current_config(bc):
    """The account-and-region-level logging singleton, or None when unset."""
    try:
        return bc.get_model_invocation_logging_configuration().get("loggingConfig")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise
        return None


def _restore_logging(bc, prior):
    if prior is None:
        bc.delete_model_invocation_logging_configuration()
    else:
        bc.put_model_invocation_logging_configuration(loggingConfig=prior)


def _put_logging_config(bc, config):
    """Put the logging config, retrying while a just-written bucket policy propagates.

    Bedrock validates the destination bucket policy synchronously on this call.
    """
    deadline = time.monotonic() + 40.0
    while True:
        try:
            bc.put_model_invocation_logging_configuration(loggingConfig=config)
            return
        except ClientError as err:
            msg = err.response["Error"].get("Message", "")
            if "Failed to validate permissions" in msg and time.monotonic() < deadline:
                time.sleep(5.0)  # bucket policy propagation lag
                continue
            if "Failed to validate permissions" in msg:
                raise AssertionError(
                    "PutModelInvocationLoggingConfiguration rejects a bucket policy matching "
                    "AWS's own documented shape with 'Failed to validate permissions for "
                    "bucket' even after a 40s propagation wait -- this account appears to have "
                    "an additional restriction (e.g. an SCP) blocking Bedrock's own internal "
                    "S3-write permission validation that is not documented and not under this "
                    "check's control."
                ) from err
            raise


def _record_keys(s3, bucket):
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=_PREFIX):
        keys += [o["Key"] for o in page.get("Contents") or []]
    return [k for k in keys if _PERMISSION_PROBE not in k]


def _read_records(s3, bucket):
    """[(key, record)] for every delivered invocation record under the prefix."""
    out = []
    for key in _record_keys(s3, bucket):
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        if key.endswith(".gz"):
            body = gzip.decompress(body)
        for line in body.decode("utf-8").splitlines():
            line = line.strip()
            if line:
                out.append((key, json.loads(line)))
    return out


def _await_record(s3, bucket, request_id, leg):
    """The (key, record) whose requestId is `request_id`; raises on timeout."""
    deadline = time.monotonic() + _DELIVERY_TIMEOUT_S
    seen = []
    while True:
        seen = _read_records(s3, bucket)
        for key, record in seen:
            if record.get("requestId") == request_id:
                return key, record
        if time.monotonic() >= deadline:
            break
        time.sleep(2.0)
    raise AssertionError(
        f"{leg}: no invocation log record carrying requestId {request_id!r} appeared under "
        f"s3://{bucket}/{_PREFIX} within {_DELIVERY_TIMEOUT_S}s; {len(seen)} record(s) were "
        f"delivered, with requestIds {[r.get('requestId') for _, r in seen]!r}"
    )


def _converse(rt, nonce):
    """One short, cheap inference whose prompt carries a nonce. Returns (response, requestId)."""
    response = rt.converse(
        modelId=MODEL_ID,
        messages=[{"role": "user", "content": [{
            "text": f"Repeat exactly this token and nothing else: {nonce}"}]}],
        inferenceConfig={"maxTokens": 40, "temperature": 0.0},
    )
    request_id = response["ResponseMetadata"]["RequestId"]
    assert request_id, f"the Converse response carried no RequestId to join on; {response!r}"
    return response, request_id


@tags("axis:happy-path", "concern:eventing", "concern:metrics", "dp:api", "plane:data", "cap:c3", "resource:account-singleton:bedrock-invocation-logging")
def run(ctx) -> None:
    """textDataDeliveryEnabled=False omits the prompt and completion bodies from the invocation-log
    record (joined on requestId), while the record and its metadata still arrive; with it True on
    the same bucket and prefix, the bodies come back verbatim.
    """
    bc = ctx.client("bedrock")
    s3 = ctx.client("s3")
    rt = ctx.client("bedrock-runtime")
    account = ctx.client("sts").get_caller_identity()["Account"]

    # ACCOUNT-and-region-level singleton: stash and register the restore before anything can fail.
    prior = _current_config(bc)
    ctx.on_cleanup(lambda: _restore_logging(bc, prior))

    bucket = ctx.unique_name("sim2real-bedrock-textoff-")
    create_kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "bedrock-invocation-logging-text-off"}]})
    s3.put_bucket_policy(Bucket=bucket, Policy=_bucket_policy(bucket, account, ctx.region))

    # ---- Leg 1: text delivery OFF ------------------------------------------------------------
    _put_logging_config(bc, {
        "s3Config": {"bucketName": bucket, "keyPrefix": _PREFIX},
        "textDataDeliveryEnabled": False,
        "imageDataDeliveryEnabled": False,
        "embeddingDataDeliveryEnabled": False,
    })
    off_config = bc.get_model_invocation_logging_configuration()["loggingConfig"]
    assert off_config["textDataDeliveryEnabled"] is False, (
        f"the stored configuration must report text delivery disabled, otherwise the leg below is "
        f"measuring the wrong thing; got {off_config!r}"
    )
    assert off_config["s3Config"]["bucketName"] == bucket, (
        f"the configuration must name the bucket just created; got {off_config!r}"
    )

    off_nonce = "sim2realoffnonce" + uuid.uuid4().hex[:12]
    off_response, off_request_id = _converse(rt, off_nonce)
    off_completion = "".join(
        b.get("text", "") for b in off_response["output"]["message"]["content"]
    )
    assert off_completion.strip(), (
        f"the disabled leg's inference must really have run and produced text, otherwise the record "
        f"below has no body to suppress; response={off_response!r}"
    )
    off_key, off_record = _await_record(s3, bucket, off_request_id, "text-delivery-off")

    # The record arrived, so the delivery path is live -- and it is the record for THIS invocation.
    assert off_record.get("schemaType") == "ModelInvocationLog", (
        f"a delivered record must declare schemaType=ModelInvocationLog; got "
        f"{off_record.get('schemaType')!r}"
    )
    assert off_record.get("operation") == "Converse", (
        f"the record must name the operation invoked; got {off_record.get('operation')!r}"
    )
    assert off_record.get("modelId") == MODEL_ID, (
        f"the record must name the model invoked; got {off_record.get('modelId')!r}"
    )
    assert off_record.get("accountId") == account, (
        f"the record must carry the live caller account {account!r}; got "
        f"{off_record.get('accountId')!r}"
    )
    assert off_record.get("region") == ctx.region, (
        f"the record must carry the region the call was made in ({ctx.region!r}); got "
        f"{off_record.get('region')!r}"
    )
    assert (off_record.get("identity") or {}).get("arn"), (
        f"the record must attribute the call to a caller identity; got "
        f"{off_record.get('identity')!r}"
    )

    # The documented key layout, derived from the live account and region rather than pinned.
    want_path = f"AWSLogs/{account}/BedrockModelInvocationLogs/{ctx.region}/"
    assert off_key.startswith(f"{_PREFIX}/"), (
        f"the delivered object must sit under the configured keyPrefix {_PREFIX!r}; got {off_key!r}"
    )
    assert want_path in off_key, (
        f"the delivered object key must carry the documented layout {want_path!r} built from the "
        f"live account and region; got {off_key!r}"
    )

    # ...and the bodies are gone. Asserted over the whole serialised record so that no defaulted
    # lookup can supply the absence the check exists to detect.
    off_blob = json.dumps(off_record)
    assert "inputBodyJson" not in off_blob, (
        f"text delivery is disabled, so the record must carry no inputBodyJson; record={off_blob[:300]}"
    )
    assert "outputBodyJson" not in off_blob, (
        f"text delivery is disabled, so the record must carry no outputBodyJson; record="
        f"{off_blob[:300]}"
    )
    assert off_nonce not in off_blob, (
        f"the prompt nonce {off_nonce!r} leaked into a delivered record even though text delivery "
        f"is disabled; record={off_blob[:300]}"
    )
    # ...and nowhere else in the bucket either.
    everything_off = json.dumps([r for _, r in _read_records(s3, bucket)])
    assert off_nonce not in everything_off, (
        f"the prompt nonce {off_nonce!r} appears in some other delivered record while text delivery "
        f"is disabled"
    )

    # ---- Leg 2: the twin control, text delivery ON ---------------------------------------------
    _put_logging_config(bc, {
        "s3Config": {"bucketName": bucket, "keyPrefix": _PREFIX},
        "textDataDeliveryEnabled": True,
        "imageDataDeliveryEnabled": False,
        "embeddingDataDeliveryEnabled": False,
    })
    on_config = bc.get_model_invocation_logging_configuration()["loggingConfig"]
    assert on_config["textDataDeliveryEnabled"] is True, (
        f"the control leg needs text delivery enabled on the SAME bucket and prefix; got "
        f"{on_config!r}"
    )

    on_nonce = "sim2realonnonce" + uuid.uuid4().hex[:12]
    on_response, on_request_id = _converse(rt, on_nonce)
    assert on_request_id != off_request_id, (
        f"the two legs must be distinct invocations; both reported requestId {on_request_id!r}"
    )
    _, on_record = _await_record(s3, bucket, on_request_id, "text-delivery-on")

    prompt_text = on_record["input"]["inputBodyJson"]["messages"][0]["content"][0]["text"]
    assert on_nonce in prompt_text, (
        f"with text delivery enabled the record must carry the prompt verbatim; got {prompt_text!r}"
    )
    completion = "".join(
        b.get("text", "") for b in on_response["output"]["message"]["content"]
    )
    logged = "".join(
        b.get("text", "") for b in on_record["output"]["outputBodyJson"]["output"]["message"]["content"]
    )
    assert logged == completion, (
        f"with text delivery enabled the record's completion must be the text the API returned; "
        f"logged {logged!r} returned {completion!r}"
    )

    # The pair is the claim: one flag, two record shapes, same wiring.
    assert "inputBodyJson" in json.dumps(on_record), (
        f"the control leg must prove the bodies come back when the flag is on, otherwise the "
        f"disabled leg's absence proves nothing; record={json.dumps(on_record)[:300]}"
    )
    assert off_nonce not in json.dumps(on_record), (
        f"the enabled leg's record must belong to its own invocation, not the earlier one; "
        f"record={json.dumps(on_record)[:300]}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
