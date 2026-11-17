"""duplicate-create-vector-bucket-preserves-bucket-state."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "duplicate-create-vector-bucket-preserves-bucket-state"
GROUP = "vector-bucket"
SERVICES = ["s3vectors"]

_ERR_NAME_TAKEN = (
    "ConflictException",
    "A vector bucket with the specified name already exists",
)


def _expect_error(fn, code, message):
    """Assert fn() raises exactly this (code, message); raises if fn() unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        assert err.get("Code") == code, err
        assert err.get("Message") == message, err
        return
    raise AssertionError(f"expected ({code!r}, {message!r}) but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A duplicate CreateVectorBucket with different tags and an explicit AES256
    encryptionConfiguration is refused, leaving the bucket's ARN, creationTime, encryption
    and tags unchanged; TagResource with the same extra tag against the bucket adds it.
    """
    s3v = ctx.client("s3vectors")
    name = ctx.unique_name("sim2real-behav-vb-")
    s3v.create_vector_bucket(
        vectorBucketName=name,
        tags={"sim2real:owner": "fidelity-check"},
    )
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=name))

    original = s3v.get_vector_bucket(vectorBucketName=name)["vectorBucket"]
    original_arn = original["vectorBucketArn"]
    original_created = original["creationTime"]
    original_encryption = original["encryptionConfiguration"]
    original_tags = s3v.list_tags_for_resource(resourceArn=original_arn)["tags"]

    extra_key, extra_value = "sim2real:added-later", "true"
    _expect_error(
        lambda: s3v.create_vector_bucket(
            vectorBucketName=name,
            tags={"sim2real:owner": "replacement", extra_key: extra_value},
            encryptionConfiguration={"sseType": "AES256"},
        ),
        *_ERR_NAME_TAKEN,
    )

    after_refusal = s3v.get_vector_bucket(vectorBucketName=name)["vectorBucket"]
    assert after_refusal["vectorBucketArn"] == original_arn, (
        f"ARN changed after a refused duplicate create: {original_arn!r} -> "
        f"{after_refusal['vectorBucketArn']!r}"
    )
    assert after_refusal["creationTime"] == original_created, (
        f"creationTime changed after a refused duplicate create: {original_created!r} -> "
        f"{after_refusal['creationTime']!r}"
    )
    assert after_refusal["encryptionConfiguration"] == original_encryption, (
        f"encryptionConfiguration changed after a refused duplicate create: "
        f"{original_encryption!r} -> {after_refusal['encryptionConfiguration']!r}"
    )
    after_refusal_tags = s3v.list_tags_for_resource(resourceArn=original_arn)["tags"]
    assert after_refusal_tags == original_tags, (
        f"tags changed after a refused duplicate create: {original_tags!r} -> "
        f"{after_refusal_tags!r}"
    )
    assert extra_key not in after_refusal_tags, after_refusal_tags

    # Legal neighbour: the same tag the refused create tried to add lands when applied
    # through TagResource against the existing bucket instead.
    s3v.tag_resource(resourceArn=original_arn, tags={extra_key: extra_value})
    final_tags = s3v.list_tags_for_resource(resourceArn=original_arn)["tags"]
    expected_tags = dict(original_tags)
    expected_tags[extra_key] = extra_value
    assert final_tags == expected_tags, (
        f"TagResource did not add {extra_key!r}; got {final_tags!r}, expected {expected_tags!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
