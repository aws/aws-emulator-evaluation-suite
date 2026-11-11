"""disabled-kms-key-refuses-new-vector-buckets-and-indexes-until-re-enabled."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disabled-kms-key-refuses-new-vector-buckets-and-indexes-until-re-enabled"
GROUP = "encryption"
SERVICES = ["kms", "s3vectors"]

_INDEXING_MESSAGE = (
    "Insufficient access to perform asynchronous indexing. Ensure that the key used to encrypt "
    "the index still exists, is active, and has a resource policy granting access to the S3 "
    "service principal 'indexing.s3vectors.amazonaws.com'."
)
_KMS_ID_OPEN = " (kms_request_id="


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """(code, message) of the error ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED: {result!r}")


def _kms_message(message: str) -> str:
    """The message with its trailing per-call ``(kms_request_id=<uuid>)`` removed.

    The suffix carries the id of the KMS call S3 Vectors made on the caller's behalf, which is
    minted per request; it is graded by form (present, a canonical UUID, closing the message)
    and everything before it is returned for an exact comparison.
    """
    head, sep, tail = (message or "").rpartition(_KMS_ID_OPEN)
    assert sep and tail.endswith(")"), f"message carries no kms_request_id suffix: {message!r}"
    rid = tail[:-1]
    assert str(uuid.UUID(rid)) == rid, f"kms_request_id {rid!r} is not a canonical UUID"
    return head


def _create_index(s3v, bucket, name, **extra):
    return s3v.create_index(vectorBucketName=bucket, indexName=name, dataType="float32",
                            dimension=2, distanceMetric="euclidean", **extra)


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:control", "plane:data")
def run(ctx) -> None:
    """A vector bucket under a customer KMS key serves put, query and get; with the key disabled,
    CreateIndex and CreateVectorBucket naming it are AccessDeniedException with exact messages and
    create nothing, and after EnableKey the same CreateIndex succeeds."""
    kms = ctx.client("kms")
    s3v = ctx.client("s3vectors")
    account = ctx.account

    policy = {"Version": "2012-10-17", "Statement": [
        {"Sid": "AccountAdmin", "Effect": "Allow",
         "Principal": {"AWS": f"arn:aws:iam::{account}:root"}, "Action": "kms:*", "Resource": "*"},
        {"Sid": "S3VectorsIndexing", "Effect": "Allow",
         "Principal": {"Service": "indexing.s3vectors.amazonaws.com"},
         "Action": ["kms:Decrypt", "kms:GenerateDataKey"], "Resource": "*",
         "Condition": {"StringEquals": {"aws:SourceAccount": account}}},
    ]}
    key_arn = kms.create_key(
        Policy=json.dumps(policy), Description="sim2real-behav s3vectors encryption key",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7),
                             "NotFoundException"))

    bucket = ctx.unique_name("sim2real-behav-s3v-kms-")
    s3v.create_vector_bucket(vectorBucketName=bucket,
                             encryptionConfiguration={"sseType": "aws:kms", "kmsKeyArn": key_arn})
    ctx.on_cleanup(_teardown(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket),
                             "NotFoundException"))
    index = ctx.unique_name("sim2real-behav-idx-")
    _create_index(s3v, bucket, index)
    ctx.on_cleanup(_teardown(lambda: s3v.delete_index(vectorBucketName=bucket, indexName=index),
                             "NotFoundException"))

    want_enc = {"sseType": "aws:kms", "kmsKeyArn": key_arn}
    got = s3v.get_vector_bucket(vectorBucketName=bucket)["vectorBucket"].get("encryptionConfiguration")
    assert got == want_enc, f"the bucket echoes encryption {got!r}"
    got = s3v.get_index(vectorBucketName=bucket, indexName=index)["index"].get("encryptionConfiguration")
    assert got == want_enc, f"the index inherited encryption {got!r}"

    # Positive control: the data plane works through the customer key.
    s3v.put_vectors(vectorBucketName=bucket, indexName=index, vectors=[
        {"key": "east", "data": {"float32": [1.0, 0.0]}},
        {"key": "north", "data": {"float32": [0.0, 1.0]}},
    ])
    hits = s3v.query_vectors(vectorBucketName=bucket, indexName=index, topK=1,
                             queryVector={"float32": [0.9, 0.1]})["vectors"]
    assert [h["key"] for h in hits] == ["east"], f"the nearest neighbour of [0.9, 0.1] was {hits!r}"
    rows = s3v.get_vectors(vectorBucketName=bucket, indexName=index, keys=["north"],
                           returnData=True)["vectors"]
    assert rows == [{"key": "north", "data": {"float32": [0.0, 1.0]}}], f"get_vectors returned {rows!r}"

    kms.disable_key(KeyId=key_arn)
    state = kms.describe_key(KeyId=key_arn)["KeyMetadata"]["KeyState"]
    assert state == "Disabled", f"the key reads {state!r} after DisableKey"

    inherited = ctx.unique_name("sim2real-behav-idx-inh-")
    ctx.on_cleanup(_teardown(lambda: s3v.delete_index(vectorBucketName=bucket, indexName=inherited),
                             "NotFoundException"))
    code, message = _error(lambda: _create_index(s3v, bucket, inherited))
    assert code == "AccessDeniedException", f"an index inheriting the disabled key got {code!r}"
    assert _kms_message(message) == _INDEXING_MESSAGE, f"inherited-key refusal message {message!r}"

    explicit = ctx.unique_name("sim2real-behav-idx-exp-")
    ctx.on_cleanup(_teardown(lambda: s3v.delete_index(vectorBucketName=bucket, indexName=explicit),
                             "NotFoundException"))
    code, message = _error(lambda: _create_index(s3v, bucket, explicit,
                                                 encryptionConfiguration=want_enc))
    assert code == "AccessDeniedException", f"an index naming the disabled key got {code!r}"
    assert _kms_message(message) == f"{key_arn} is disabled.", f"explicit-key refusal message {message!r}"

    second = ctx.unique_name("sim2real-behav-s3v-kms2-")
    ctx.on_cleanup(_teardown(lambda: s3v.delete_vector_bucket(vectorBucketName=second),
                             "NotFoundException"))
    code, message = _error(lambda: s3v.create_vector_bucket(vectorBucketName=second,
                                                             encryptionConfiguration=want_enc))
    assert code == "AccessDeniedException", f"a bucket naming the disabled key got {code!r}"
    assert _kms_message(message) == f"{key_arn} is disabled.", f"bucket refusal message {message!r}"

    for name in (inherited, explicit):
        code, message = _error(lambda: s3v.get_index(vectorBucketName=bucket, indexName=name))
        assert (code, message) == ("NotFoundException", "The specified index could not be found"), (
            f"a refused index reads back as {(code, message)!r}")
    code, message = _error(lambda: s3v.get_vector_bucket(vectorBucketName=second))
    assert (code, message) == ("NotFoundException", "The specified vector bucket could not be found"), (
        f"the refused bucket reads back as {(code, message)!r}")

    kms.enable_key(KeyId=key_arn)
    deadline = time.monotonic() + 120
    while True:
        try:
            _create_index(s3v, bucket, inherited)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(5)
    got = s3v.get_index(vectorBucketName=bucket, indexName=inherited)["index"].get("encryptionConfiguration")
    assert got == want_enc, f"the index created after re-enabling inherited {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
