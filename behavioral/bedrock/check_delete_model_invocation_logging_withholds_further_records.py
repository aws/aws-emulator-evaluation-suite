"""delete-model-invocation-logging-withholds-further-records."""
from __future__ import annotations

import gzip
import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-model-invocation-logging-withholds-further-records"
GROUP = "observability"
SERVICES = ["bedrock"]

# The model invocation logging configuration is an account-and-region singleton, so this check
# must not run concurrently with other Bedrock invocation logging checks.

MODEL_ID = "amazon.nova-lite-v1:0"

_PREFIX = "sim2real"
_PERMISSION_PROBE = "amazon-bedrock-logs-permission-check"
_DELIVERY_TIMEOUT_S = 110.0
_ABSENCE_FLOOR_S = 90.0
_REDELIVERY_FLOOR_S = 120.0
_POLL_S = 2.0


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


def _record_keys(s3, bucket):
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=_PREFIX):
        keys += [o["Key"] for o in page.get("Contents") or []]
    return sorted(k for k in keys if _PERMISSION_PROBE not in k)


def _read_records(s3, bucket):
    out = []
    for key in _record_keys(s3, bucket):
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        if key.endswith(".gz"):
            body = gzip.decompress(body)
        for line in body.decode("utf-8").splitlines():
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def _find(records, request_id):
    for record in records:
        if record.get("requestId") == request_id:
            return record
    return None


def _await_record(s3, bucket, request_id, leg, timeout_s):
    """Returns (record, seconds_waited). Raises on timeout -- a missing record is a failure."""
    started = time.monotonic()
    deadline = started + timeout_s
    while True:
        records = _read_records(s3, bucket)
        found = _find(records, request_id)
        if found is not None:
            return found, time.monotonic() - started
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{leg}: no invocation log record carrying requestId {request_id!r} appeared under "
                f"s3://{bucket}/{_PREFIX} within {timeout_s}s; {len(records)} record(s) present, "
                f"requestIds {[r.get('requestId') for r in records]!r}"
            )
        time.sleep(_POLL_S)


def _enable(bc, bucket):
    bc.put_model_invocation_logging_configuration(loggingConfig={
        "s3Config": {"bucketName": bucket, "keyPrefix": _PREFIX},
        "textDataDeliveryEnabled": True,
        "imageDataDeliveryEnabled": False,
        "embeddingDataDeliveryEnabled": False,
    })


def _converse(rt, nonce):
    response = rt.converse(
        modelId=MODEL_ID,
        messages=[{"role": "user", "content": [{
            "text": f"Repeat exactly this token and nothing else: {nonce}"}]}],
        inferenceConfig={"maxTokens": 40, "temperature": 0.0},
    )
    request_id = response["ResponseMetadata"]["RequestId"]
    assert request_id, f"the Converse response carried no RequestId to join on; {response!r}"
    return request_id


@tags("axis:negative-delivery", "concern:eventing", "dp:api", "plane:data", "cap:c3", "resource:account-singleton:bedrock-invocation-logging")
def run(ctx) -> None:
    """Deleting the model invocation logging configuration stops delivery: a later invocation leaves
    no record in the configured bucket, and re-putting the configuration makes delivery resume.

    Reference: https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html
    """
    bc = ctx.client("bedrock")
    s3 = ctx.client("s3")
    rt = ctx.client("bedrock-runtime")
    account = ctx.client("sts").get_caller_identity()["Account"]

    prior = _current_config(bc)
    ctx.on_cleanup(lambda: _restore_logging(bc, prior))

    bucket = ctx.unique_name("sim2real-bedrock-logstop-")
    create_kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "bedrock-invocation-logging-stop"}]})
    s3.put_bucket_policy(Bucket=bucket, Policy=_bucket_policy(bucket, account, ctx.region))

    # ---- Leg A: prove delivery works here, and MEASURE how long it takes ----------------------
    _enable(bc, bucket)
    live = bc.get_model_invocation_logging_configuration()["loggingConfig"]
    assert live["s3Config"]["bucketName"] == bucket, (
        f"the configuration must name the bucket just created; got {live!r}"
    )

    nonce_a = "sim2realnonceA" + uuid.uuid4().hex[:12]
    request_a = _converse(rt, nonce_a)
    record_a, latency = _await_record(s3, bucket, request_a, "leg-A-positive-control",
                                     _DELIVERY_TIMEOUT_S)
    assert record_a.get("operation") == "Converse", (
        f"leg A's record must belong to the Converse call that produced it; got "
        f"{record_a.get('operation')!r}"
    )
    assert nonce_a in json.dumps(record_a), (
        f"leg A's record must carry its own prompt nonce {nonce_a!r}, otherwise the measured latency "
        f"is not a delivery latency; record={json.dumps(record_a)[:300]}"
    )

    # ---- Delete the configuration, and prove the control-plane read agrees -------------------
    # Snapshot the requestIds already delivered rather than the object KEYS: Bedrock batches records,
    # so a leg-A record can legitimately land after the delete under a new key. What must not happen
    # is a NEW requestId appearing.
    ids_at_delete = {r.get("requestId") for r in _read_records(s3, bucket)}
    bc.delete_model_invocation_logging_configuration()
    assert _current_config(bc) is None, (
        f"after DeleteModelInvocationLoggingConfiguration the account must report no logging "
        f"configuration; got {_current_config(bc)!r}"
    )

    # ---- Leg B: the withheld delivery, held for >= 3L ------------------------------------------
    nonce_b = "sim2realnonceB" + uuid.uuid4().hex[:12]
    request_b = _converse(rt, nonce_b)
    # The absence is held for three times the delivery latency measured in leg A, with a floor.
    hold_s = max(3.0 * latency, _ABSENCE_FLOOR_S)
    hold_deadline = time.monotonic() + hold_s
    while True:
        records = _read_records(s3, bucket)
        assert _find(records, request_b) is None, (
            f"a record for requestId {request_b!r} was delivered to s3://{bucket}/{_PREFIX} after "
            f"the logging configuration was deleted; leg A's delivery latency was {latency:.1f}s so "
            f"this record arrived on a path that should have been switched off"
        )
        assert nonce_b not in json.dumps(records), (
            f"leg B's prompt nonce {nonce_b!r} reached a delivered record after the logging "
            f"configuration was deleted"
        )
        if time.monotonic() >= hold_deadline:
            break
        time.sleep(_POLL_S)

    # Second independent observable: not merely "leg B's record is missing" but "no NEW invocation was
    # logged at all", so a target that delivers leg B under a fabricated requestId is caught too.
    ids_after_hold = {r.get("requestId") for r in _read_records(s3, bucket)}
    assert ids_after_hold <= ids_at_delete, (
        f"no new invocation may be logged to s3://{bucket}/{_PREFIX} while logging is deleted, yet "
        f"requestId(s) {sorted(ids_after_hold - ids_at_delete)!r} appeared over {hold_s:.0f}s "
        f"(>= 3x leg A's measured {latency:.1f}s delivery latency); ids at delete were "
        f"{sorted(ids_at_delete)!r}"
    )

    # ---- Leg C: repair ONLY the configuration and demand the record back ----------------------
    _enable(bc, bucket)
    restored = bc.get_model_invocation_logging_configuration()["loggingConfig"]
    assert restored["s3Config"]["bucketName"] == bucket, (
        f"the restored configuration must name the same bucket; got {restored!r}"
    )
    nonce_c = "sim2realnonceC" + uuid.uuid4().hex[:12]
    request_c = _converse(rt, nonce_c)
    record_c, _ = _await_record(
        s3, bucket, request_c, "leg-C-redelivery",
        max(3.0 * latency, _REDELIVERY_FLOOR_S),
    )
    assert nonce_c in json.dumps(record_c), (
        f"leg C's record must carry its own prompt nonce {nonce_c!r}; "
        f"record={json.dumps(record_c)[:300]}"
    )

    # ...and leg B's invocation is STILL absent, so the resume did not retroactively flush the
    # withheld record. A target that buffers everything and drains on re-enable fails here.
    final_records = _read_records(s3, bucket)
    assert _find(final_records, request_b) is None, (
        f"the invocation made while logging was deleted (requestId {request_b!r}) appeared after "
        f"logging was re-enabled, so it was buffered rather than withheld"
    )
    assert nonce_b not in json.dumps(final_records), (
        f"leg B's prompt nonce {nonce_b!r} appeared in a record after logging was re-enabled"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
