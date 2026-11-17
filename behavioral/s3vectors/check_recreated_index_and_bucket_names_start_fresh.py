"""recreated-index-and-bucket-names-start-fresh."""

from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "recreated-index-and-bucket-names-start-fresh"
GROUP = "error-semantics"
SERVICES = ["s3vectors"]

ERR_NOT_FOUND = "NotFoundException"
MSG_BUCKET_NOT_FOUND = "The specified vector bucket could not be found"
MSG_POLICY_NOT_FOUND = "The specified vector bucket policy could not be found"

_OLD_DIMENSION = 3
_NEW_DIMENSION = 5
_KEY_BEFORE_DELETE = "vec-before-delete"


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _teardown(undo, *not_found: str):
    """A cleanup running undo() where a failed delete raises; a not_found code means it is gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "concern:representation", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A recreated index's name carries no vectors and reports its new configuration, not the
    old one; a recreated bucket's name carries no indexes, tags or policy, and a mutation
    against the bucket while deleted is refused NotFoundException.
    """
    s3v = ctx.client("s3vectors")

    # --- Part 1: a deleted INDEX's name, recreated, is a fresh resource.
    bucket1 = ctx.unique_name("sim2real-s3v-fresh-vb1-")
    s3v.create_vector_bucket(vectorBucketName=bucket1)
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket1))

    index1 = ctx.unique_name("sim2real-s3v-fresh-idx-")
    s3v.create_index(
        vectorBucketName=bucket1, indexName=index1,
        dataType="float32", dimension=_OLD_DIMENSION, distanceMetric="euclidean",
    )
    ctx.on_cleanup(lambda: s3v.delete_index(vectorBucketName=bucket1, indexName=index1))

    s3v.put_vectors(
        vectorBucketName=bucket1, indexName=index1,
        vectors=[{"key": _KEY_BEFORE_DELETE, "data": {"float32": [1.0, 0.0, 0.0]}}],
    )

    # Positive control: the key is readable before anything is deleted.
    before = s3v.get_vectors(
        vectorBucketName=bucket1, indexName=index1, keys=[_KEY_BEFORE_DELETE], returnData=True,
    )["vectors"]
    assert len(before) == 1 and before[0]["key"] == _KEY_BEFORE_DELETE, (
        f"expected {_KEY_BEFORE_DELETE!r} to be readable before deletion, got {before!r}"
    )
    assert before[0]["data"]["float32"] == [1.0, 0.0, 0.0], (
        f"expected the pre-delete data [1.0, 0.0, 0.0], got {before[0]['data']['float32']!r}"
    )

    s3v.delete_index(vectorBucketName=bucket1, indexName=index1)

    s3v.create_index(
        vectorBucketName=bucket1, indexName=index1,
        dataType="float32", dimension=_NEW_DIMENSION, distanceMetric="euclidean",
    )

    recreated = s3v.get_index(vectorBucketName=bucket1, indexName=index1)["index"]
    assert recreated["dimension"] == _NEW_DIMENSION, (
        f"the re-created index must report the new dimension {_NEW_DIMENSION}, got "
        f"{recreated['dimension']!r}"
    )

    vectors_after = s3v.list_vectors(vectorBucketName=bucket1, indexName=index1)["vectors"]
    assert vectors_after == [], (
        f"the re-created index must hold no vectors, but ListVectors returned {vectors_after!r}"
    )

    absent = s3v.get_vectors(
        vectorBucketName=bucket1, indexName=index1, keys=[_KEY_BEFORE_DELETE], returnData=True,
    )["vectors"]
    assert absent == [], (
        f"the key {_KEY_BEFORE_DELETE!r} written before the delete must be absent from the "
        f"re-created index, but GetVectors returned {absent!r}"
    )

    # --- Part 2: a deleted BUCKET's name, recreated, is a fresh resource.
    bucket2 = ctx.unique_name("sim2real-s3v-fresh-vb2-")
    bucket2_arn = s3v.create_vector_bucket(vectorBucketName=bucket2)["vectorBucketArn"]
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket2))

    s3v.tag_resource(resourceArn=bucket2_arn, tags={"generation": "one"})

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowOldGenerationList",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
                "Action": "s3vectors:ListVectors",
                "Resource": f"{bucket2_arn}/*",
            }
        ],
    }
    s3v.put_vector_bucket_policy(vectorBucketName=bucket2, policy=json.dumps(policy))

    index2 = ctx.unique_name("sim2real-s3v-fresh-idx2-")
    s3v.create_index(
        vectorBucketName=bucket2, indexName=index2,
        dataType="float32", dimension=_OLD_DIMENSION, distanceMetric="euclidean",
    )
    ctx.on_cleanup(_teardown(
        lambda: s3v.delete_index(vectorBucketName=bucket2, indexName=index2), ERR_NOT_FOUND,
    ))

    # Positive controls: the old generation really carries a tag, a policy and an index.
    tags_before = s3v.list_tags_for_resource(resourceArn=bucket2_arn)["tags"]
    assert tags_before == {"generation": "one"}, (
        f"expected the old generation to carry its tag, got {tags_before!r}"
    )
    policy_before = json.loads(
        s3v.get_vector_bucket_policy(vectorBucketName=bucket2)["policy"]
    )
    assert policy_before == policy, (
        f"expected the old generation's policy to round-trip, got {policy_before!r}"
    )
    indexes_before = [i["indexName"] for i in s3v.list_indexes(vectorBucketName=bucket2)["indexes"]]
    assert indexes_before == [index2], (
        f"expected the old generation to list exactly [{index2!r}], got {indexes_before!r}"
    )

    # Empty the bucket (DeleteVectorBucket refuses a bucket still holding an index), then delete it.
    s3v.delete_index(vectorBucketName=bucket2, indexName=index2)
    s3v.delete_vector_bucket(vectorBucketName=bucket2)

    create_code, create_message = _error(
        lambda: s3v.create_index(
            vectorBucketName=bucket2, indexName=ctx.unique_name("sim2real-s3v-doomed-idx-"),
            dataType="float32", dimension=_OLD_DIMENSION, distanceMetric="euclidean",
        )
    )
    assert create_code == ERR_NOT_FOUND, (
        f"CreateIndex against the deleted bucket must be refused {ERR_NOT_FOUND}, got {create_code!r}"
    )
    assert create_message == MSG_BUCKET_NOT_FOUND, (
        f"unexpected CreateIndex {create_code} message {create_message!r}"
    )

    recreated_arn = s3v.create_vector_bucket(vectorBucketName=bucket2)["vectorBucketArn"]

    indexes_after = s3v.list_indexes(vectorBucketName=bucket2)["indexes"]
    assert indexes_after == [], (
        f"the re-created bucket must hold no indexes, but ListIndexes returned {indexes_after!r}"
    )

    tags_after = s3v.list_tags_for_resource(resourceArn=recreated_arn)["tags"]
    assert tags_after == {}, (
        f"the re-created bucket must carry no tags from the old generation, got {tags_after!r}"
    )

    policy_code, policy_message = _error(
        lambda: s3v.get_vector_bucket_policy(vectorBucketName=bucket2)
    )
    assert policy_code == ERR_NOT_FOUND, (
        f"the re-created bucket must have no policy, expected {ERR_NOT_FOUND}, got {policy_code!r}"
    )
    assert policy_message == MSG_POLICY_NOT_FOUND, (
        f"unexpected GetVectorBucketPolicy {policy_code} message {policy_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
