"""put-record-on-sse-kms-stream-denied-without-grant-then-decrypts."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-record-on-sse-kms-stream-denied-without-grant-then-decrypts"
GROUP = "kinesis-sse-kms-permission-chain"
SERVICES = ["iam", "kinesis", "kms", "sts"]

_TAG = "sim2real-kinesis-kms-chain"
_SESSION_NAME = "sim2real-kinesis-session"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "concern:data-plane", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A role with only kinesis:PutRecord/GetRecords is refused KMSAccessDeniedException once a
    stream is server-side encrypted under a CMK the role has no grant on; granting it
    kms:GenerateDataKey and kms:Decrypt on that key makes the same call succeed and decrypt.

    Reference: https://docs.aws.amazon.com/streams/latest/dev/what-is-sse.html
    """
    kinesis = ctx.client("kinesis")
    kms = ctx.client("kms")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    stream = _new_stream(ctx, kinesis)
    shard_id = _only_shard_id(kinesis, stream)
    role_name, role_arn = _new_role(ctx, iam, sts.get_caller_identity()["Account"])
    _put_role_policy(iam, role_name, "kinesis-rw", [
        {"Effect": "Allow",
         "Action": ["kinesis:PutRecord", "kinesis:GetRecords", "kinesis:GetShardIterator"],
         "Resource": f"arn:aws:kinesis:{ctx.region}:{ctx.account}:stream/{stream}"},
    ])
    role_creds = _assume(sts, role_arn)
    kinesis_as_role = ctx.client("kinesis", creds=role_creds)

    # Positive control: the role's plain kinesis grant works on its own, before encryption exists.
    control_seq = _put_record(kinesis_as_role, stream, b"sim2real-control-payload", "pk-control")
    control_count = len(_drain(kinesis, stream, shard_id))
    assert control_count == 1, (
        f"after the control write the shard holds {control_count} record(s), expected 1")

    # Break exactly one thing: turn on SSE-KMS under a CMK the role has no grant on.
    key_arn = _new_key(ctx, kms)
    _start_encryption(kinesis, stream, key_arn)

    code, message = _refusal(lambda: _put_record(kinesis_as_role, stream, b"sim2real-denied-payload",
                                                   "pk-denied"))
    assert code == "KMSAccessDeniedException", (
        f"PutRecord with no kms:GenerateDataKey/kms:Decrypt grant on {key_arn!r} must be refused "
        f"KMSAccessDeniedException, got {code!r}: {message!r}")
    assumed_arn = f"arn:aws:sts::{ctx.account}:assumed-role/{role_name}/{_SESSION_NAME}"
    expected_message = (
        f"User: {assumed_arn} is not authorized to perform: kms:GenerateDataKey on "
        f"resource: {key_arn} because no identity-based policy allows the kms:GenerateDataKey action"
    )
    assert message == expected_message, f"unexpected refusal wording: {message!r}"

    # The effect is absent: an independent admin read still shows only the control record.
    still_one = len(_drain(kinesis, stream, shard_id))
    assert still_one == control_count, (
        f"after the refused PutRecord the shard holds {still_one} record(s), expected the control's "
        f"{control_count} unchanged")

    # Restore exactly the one missing grant, on exactly this key.
    _put_role_policy(iam, role_name, "kms-envelope", [
        {"Effect": "Allow", "Action": ["kms:GenerateDataKey", "kms:Decrypt"], "Resource": key_arn},
    ])
    recovered_seq = _poll(
        lambda: _outcome(lambda: _put_record(kinesis_as_role, stream, b"sim2real-recovered-payload",
                                              "pk-recovered")),
        lambda o: o[0] == "OK", description="PutRecord after granting the KMS envelope permissions")
    assert recovered_seq[0] == "OK", f"the identical call must now succeed, got {recovered_seq!r}"

    # Independent terminal read, through GetRecords rather than PutRecord, at the far end.
    records = _drain(kinesis, stream, shard_id)
    assert len(records) == 2, f"the shard holds {len(records)} record(s) after recovery, expected 2"
    by_seq = {r["SequenceNumber"]: r["Data"] for r in records}
    assert by_seq.get(control_seq) == b"sim2real-control-payload", (
        f"the control record's bytes changed: {by_seq.get(control_seq)!r}")
    assert by_seq.get(recovered_seq[1]) == b"sim2real-recovered-payload", (
        f"the recovered write decrypts to {by_seq.get(recovered_seq[1])!r}, expected the plaintext "
        f"sent")


def _new_stream(ctx, kinesis) -> str:
    name = ctx.unique_name("sim2real-kinesis-kms-")
    kinesis.create_stream(StreamName=name, ShardCount=1,
                           Tags={"sim2real": _TAG})
    ctx.on_cleanup(_teardown(lambda: kinesis.delete_stream(StreamName=name),
                              "ResourceNotFoundException"))
    _poll(lambda: kinesis.describe_stream_summary(StreamName=name)
          ["StreamDescriptionSummary"]["StreamStatus"],
          lambda s: s == "ACTIVE", description=f"stream {name} reaching ACTIVE")
    return name


def _only_shard_id(kinesis, stream: str) -> str:
    """ListShards can still see CREATING for a moment after DescribeStreamSummary reports ACTIVE."""
    deadline = time.monotonic() + 30
    while True:
        try:
            shards = kinesis.list_shards(StreamName=stream)["Shards"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceInUseException" or (
                    time.monotonic() > deadline):
                raise
            time.sleep(2)
    assert len(shards) == 1, f"expected exactly one shard, found {len(shards)}: {shards!r}"
    return shards[0]["ShardId"]


def _start_encryption(kinesis, stream: str, key_arn: str) -> None:
    """A just-created CMK can read back as KMSNotFoundException for a few seconds; retry only that."""
    deadline = time.monotonic() + 60
    while True:
        try:
            kinesis.start_stream_encryption(StreamName=stream, EncryptionType="KMS", KeyId=key_arn)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "KMSNotFoundException" or (
                    time.monotonic() > deadline):
                raise
            time.sleep(3)
    _poll(lambda: kinesis.describe_stream_summary(StreamName=stream)
          ["StreamDescriptionSummary"]["StreamStatus"],
          lambda s: s == "ACTIVE", description=f"stream {stream} re-ACTIVE after StartStreamEncryption")


def _new_key(ctx, kms) -> str:
    key = kms.create_key(Description="sim2real kinesis SSE-KMS permission chain",
                          Tags=[{"TagKey": "sim2real", "TagValue": _TAG}])["KeyMetadata"]
    ctx.on_cleanup(lambda: _schedule_deletion(kms, key["KeyId"]))
    return key["Arn"]


def _schedule_deletion(kms, key_id: str) -> None:
    try:
        kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "KMSInvalidStateException":
            raise


def _new_role(ctx, iam, account: str) -> tuple[str, str]:
    name = ctx.unique_name("sim2real-kinesis-kms-role-")
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
         "Action": "sts:AssumeRole"}]}
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                            Tags=[{"Key": "sim2real", "Value": _TAG}])["Role"]
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    return name, role["Arn"]


def _delete_role(iam, name: str) -> None:
    try:
        for policy in iam.list_role_policies(RoleName=name)["PolicyNames"]:
            iam.delete_role_policy(RoleName=name, PolicyName=policy)
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _put_role_policy(iam, role_name: str, policy_name: str, statements: list[dict]) -> None:
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name,
                         PolicyDocument=json.dumps({"Version": "2012-10-17",
                                                     "Statement": statements}))


def _assume(sts, role_arn: str) -> dict:
    """A freshly created role is not always assumable yet; retry the propagation window, bounded."""
    deadline = time.monotonic() + 90
    while True:
        try:
            c = sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION_NAME)["Credentials"]
            return {"aws_access_key_id": c["AccessKeyId"],
                    "aws_secret_access_key": c["SecretAccessKey"],
                    "aws_session_token": c["SessionToken"]}
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDenied" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _put_record(client, stream: str, data: bytes, partition_key: str) -> str:
    """PutRecord's SequenceNumber, retrying only a freshly-assumed session's auth-cache lag."""
    deadline = time.monotonic() + 30
    while True:
        try:
            return client.put_record(StreamName=stream, Data=data,
                                      PartitionKey=partition_key)["SequenceNumber"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "UnrecognizedClientException" or (
                    time.monotonic() > deadline):
                raise
            time.sleep(2)


def _drain(kinesis, stream: str, shard_id: str, *, max_reads: int = 10) -> list[dict]:
    iterator = kinesis.get_shard_iterator(StreamName=stream, ShardId=shard_id,
                                           ShardIteratorType="TRIM_HORIZON")["ShardIterator"]
    records: list[dict] = []
    for _ in range(max_reads):
        resp = kinesis.get_records(ShardIterator=iterator, Limit=100)
        records.extend(resp["Records"])
        iterator = resp.get("NextShardIterator")
        if not iterator or (not resp["Records"] and resp.get("MillisBehindLatest", 0) == 0):
            break
        time.sleep(0.5)
    return records


def _refusal(fn) -> tuple[str, str]:
    """(code, message) of a call real AWS refuses; an unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected this call to be refused, but it succeeded: {result!r}")


def _outcome(fn):
    """("OK", value) on success, else (code, None). Only "OK" is compared for equality."""
    try:
        return "OK", fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], None


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _poll(probe, predicate, *, timeout_s: float = 90.0, interval_s: float = 3.0,
          description: str = "condition"):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)
        last = probe()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
