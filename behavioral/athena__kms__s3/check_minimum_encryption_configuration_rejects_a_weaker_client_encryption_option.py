"""minimum-encryption-configuration-rejects-a-weaker-client-encryption-option."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "minimum-encryption-configuration-rejects-a-weaker-client-encryption-option"
GROUP = "server-side"
SERVICES = ["athena", "kms", "s3"]


def _empty_and_delete_bucket(s3, bucket):
    """Delete every object, then the bucket; Athena writes `<qid>.csv` and `.csv.metadata`."""
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        objs = page.get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
    s3.delete_bucket(Bucket=bucket)


def _make_bucket(ctx, prefix):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name(prefix)
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "athena-minimum-encryption"},
        {"Key": "sim2real:managed", "Value": "true"},
    ]})
    return bucket


def _make_key(ctx):
    """A customer-managed symmetric KMS key for result encryption.

    ScheduleKeyDeletion's minimum window is 7 days, so the key ends in PendingDeletion.
    """
    kms = ctx.client("kms")
    key = kms.create_key(
        Description=f"sim2real {CHECK}",
        KeyUsage="ENCRYPT_DECRYPT",
        Tags=[{"TagKey": "sim2real", "TagValue": "athena-minimum-encryption"},
              {"TagKey": "sim2real:managed", "TagValue": "true"}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: ctx.client("kms").schedule_key_deletion(
        KeyId=key["KeyId"], PendingWindowInDays=7))
    described = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
    assert described["Enabled"] is True, (
        f"the key must be usable before any encryption is concluded from it, got {described!r}")
    return described["Arn"]


def _wait_terminal(athena, qid, timeout_s=300, interval_s=2):
    """Poll GetQueryExecution to a terminal state with a bounded deadline; raise on timeout."""
    terminal = ("SUCCEEDED", "FAILED", "CANCELLED")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]["State"]
        if state in terminal:
            return state
        time.sleep(interval_s)
    raise AssertionError(
        f"query {qid} did not reach a terminal state within {timeout_s}s (last={state})")


_BELOW_FLOOR_MESSAGE = (
    "The encryption option in the request does not meet the minimum encryption option specified "
    "in the workgroup. The valid option(s) are: [SSE_KMS, CSE_KMS]."
)


def _error(fn):
    """The botocore ``(Error.Code, Error.Message)`` raised by fn(); raise on unexpected success."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call was expected to raise a ClientError but SUCCEEDED")


def _keys_under(s3, bucket, prefix):
    """Every key under `prefix`, sorted."""
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return sorted(keys)


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """With EnableMinimumEncryptionConfiguration at SSE_KMS, an SSE_S3 query is refused and writes
    nothing, an SSE_KMS result is encrypted with this run's key, and dropping the floor lets the
    same SSE_S3 query succeed with AES256.

    Reference: https://docs.aws.amazon.com/athena/latest/ug/workgroups-minimum-encryption.html
    """
    athena = ctx.client("athena")
    s3 = ctx.client("s3")
    key_arn = _make_key(ctx)

    bucket = _make_bucket(ctx, "sim2real-xsvc-athena-enc-")
    prefix = "results/"
    out = f"s3://{bucket}/{prefix}"

    wg = ctx.unique_name("sim2real-xsvc-athena-wg-minenc-")
    athena.create_work_group(
        Name=wg,
        Configuration={
            "ResultConfiguration": {
                "OutputLocation": out,
                "EncryptionConfiguration": {"EncryptionOption": "SSE_KMS", "KmsKey": key_arn},
            },
            # The documented combination: the floor is only meaningful when client settings are NOT
            # overridden outright, because otherwise nothing the client asks for is consulted.
            "EnforceWorkGroupConfiguration": False,
            "EnableMinimumEncryptionConfiguration": True,
        },
        Tags=[{"Key": "sim2real", "Value": "athena-minimum-encryption"},
              {"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg, RecursiveDeleteOption=True))
    cfg = athena.get_work_group(WorkGroup=wg)["WorkGroup"]["Configuration"]
    assert cfg["EnableMinimumEncryptionConfiguration"] is True, (
        f"the floor must be observably in place before its effect is asserted; GetWorkGroup "
        f"reported EnableMinimumEncryptionConfiguration="
        f"{cfg.get('EnableMinimumEncryptionConfiguration')!r}")
    assert cfg["ResultConfiguration"]["EncryptionConfiguration"]["EncryptionOption"] == "SSE_KMS", (
        f"the floor level must be SSE_KMS for the SSE_S3 request below to be strictly weaker; got "
        f"{cfg['ResultConfiguration']['EncryptionConfiguration']!r}")

    marker = ctx.unique_name("").replace("-", "")[:12]
    sql = f"SELECT 'enc-{marker}' AS marker"
    kms_config = {
        "OutputLocation": out,
        "EncryptionConfiguration": {"EncryptionOption": "SSE_KMS", "KmsKey": key_arn},
    }
    s3_config = {
        "OutputLocation": out,
        "EncryptionConfiguration": {"EncryptionOption": "SSE_S3"},
    }

    # --- positive control: at the floor, and the bytes really are encrypted.
    ok_qid = athena.start_query_execution(
        QueryString=sql, WorkGroup=wg, ResultConfiguration=kms_config)["QueryExecutionId"]
    ok_state = _wait_terminal(athena, ok_qid)
    ok_reason = athena.get_query_execution(QueryExecutionId=ok_qid)["QueryExecution"][
        "Status"].get("StateChangeReason")
    assert ok_state == "SUCCEEDED", (
        f"a request AT the floor (SSE_KMS with the workgroup's own key) must succeed, proving the "
        f"wiring is otherwise healthy; got {ok_state!r} / {ok_reason!r}")
    ok_key = f"{prefix}{ok_qid}.csv"
    head = s3.head_object(Bucket=bucket, Key=ok_key)
    assert head["ServerSideEncryption"] == "aws:kms", (
        f"the result object {ok_key!r} must be stored SSE-KMS encrypted, S3 reported "
        f"ServerSideEncryption={head.get('ServerSideEncryption')!r}")
    assert head["SSEKMSKeyId"] == key_arn, (
        f"the result object must be encrypted with the key this run created ({key_arn}), S3 "
        f"reported {head.get('SSEKMSKeyId')!r}")
    meta_head = s3.head_object(Bucket=bucket, Key=f"{ok_key}.metadata")
    assert meta_head["ServerSideEncryption"] == "aws:kms", (
        f"the `.csv.metadata` sibling carries the result schema and must be encrypted the same way, "
        f"S3 reported ServerSideEncryption={meta_head.get('ServerSideEncryption')!r}")
    before_keys = _keys_under(s3, bucket, prefix)

    # --- break exactly one thing: ask for the level BELOW the floor.
    code, message = _error(lambda: athena.start_query_execution(
        QueryString=sql, WorkGroup=wg, ResultConfiguration=s3_config))
    assert code == "InvalidRequestException", (
        f"SSE_S3 is below the SSE_KMS floor this workgroup enforces, so the identical query with "
        f"only the EncryptionOption changed must be refused with InvalidRequestException; got "
        f"{code!r}")
    assert message == _BELOW_FLOOR_MESSAGE, (
        f"the below-floor refusal said {message!r}, expected {_BELOW_FLOOR_MESSAGE!r}")

    # --- effect absent: nothing new was written under the output prefix.
    after_keys = _keys_under(s3, bucket, prefix)
    assert after_keys == before_keys, (
        f"a refused query must write nothing: the output prefix held {before_keys!r} before the "
        f"refusal and {after_keys!r} after")

    # --- restore: drop the floor, and the identical request must now be honoured,
    #     with the weaker encryption actually applied rather than silently upgraded.
    athena.update_work_group(
        WorkGroup=wg, ConfigurationUpdates={"EnableMinimumEncryptionConfiguration": False})
    dropped = athena.get_work_group(WorkGroup=wg)["WorkGroup"]["Configuration"]
    assert dropped["EnableMinimumEncryptionConfiguration"] is False, (
        f"UpdateWorkGroup must drop the floor; GetWorkGroup reported "
        f"{dropped.get('EnableMinimumEncryptionConfiguration')!r}")
    weak_qid = athena.start_query_execution(
        QueryString=sql, WorkGroup=wg, ResultConfiguration=s3_config)["QueryExecutionId"]
    weak_state = _wait_terminal(athena, weak_qid)
    weak_reason = athena.get_query_execution(QueryExecutionId=weak_qid)["QueryExecution"][
        "Status"].get("StateChangeReason")
    assert weak_state == "SUCCEEDED", (
        f"with the floor removed the identical SSE_S3 request must succeed, proving the refusal was "
        f"the floor and not the encryption option itself; got {weak_state!r} / {weak_reason!r}")
    weak_head = s3.head_object(Bucket=bucket, Key=f"{prefix}{weak_qid}.csv")
    assert weak_head["ServerSideEncryption"] == "AES256", (
        f"with the floor removed the client's SSE_S3 choice must actually be applied, not upgraded: "
        f"S3 reported ServerSideEncryption={weak_head.get('ServerSideEncryption')!r}")
    assert "SSEKMSKeyId" not in weak_head, (
        f"an SSE-S3 object is not encrypted with a KMS key, so S3 must report no SSEKMSKeyId; got "
        f"{weak_head.get('SSEKMSKeyId')!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
