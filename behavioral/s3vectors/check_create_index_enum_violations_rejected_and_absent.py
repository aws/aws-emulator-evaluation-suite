"""create-index-enum-violations-rejected-and-absent."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "create-index-enum-violations-rejected-and-absent"
GROUP = "index"
SERVICES = ["s3vectors"]

_DIMENSION = 3

_ERR_BAD_METRIC = (
    "ValidationException",
    "1 validation error detected. Value at '/distanceMetric' failed to satisfy constraint: "
    "Member must satisfy enum value set: [euclidean, cosine]",
)
_ERR_BAD_DATA_TYPE = (
    "ValidationException",
    "1 validation error detected. Value at '/dataType' failed to satisfy constraint: "
    "Member must satisfy enum value set: [float32]",
)
_ERR_INDEX_NOT_FOUND = ("NotFoundException", "The specified index could not be found")


def _create_bucket(ctx, s3v):
    name = ctx.unique_name("sim2real-behav-vb-")
    s3v.create_vector_bucket(vectorBucketName=name)
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=name))
    return name


def _expect_error(fn, code, message):
    """Assert fn() raises exactly this (code, message); raises if fn() succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        assert err.get("Code") == code, err
        assert err.get("Message") == message, err
        return
    raise AssertionError(f"expected ({code!r}, {message!r}) but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateIndex refuses an out-of-enum distanceMetric and an out-of-enum dataType, each with
    its exact enum-violation message and no index created; both legal distanceMetric values
    succeed in the same bucket, each echoed back by GetIndex."""
    s3v = ctx.client("s3vectors")
    bucket = _create_bucket(ctx, s3v)

    bad_metric_name = ctx.unique_name("sim2real-behav-badmetric-")
    _expect_error(
        lambda: s3v.create_index(
            vectorBucketName=bucket,
            indexName=bad_metric_name,
            dimension=_DIMENSION,
            distanceMetric="manhattan",
            dataType="float32",
        ),
        *_ERR_BAD_METRIC,
    )

    bad_data_type_name = ctx.unique_name("sim2real-behav-baddtype-")
    _expect_error(
        lambda: s3v.create_index(
            vectorBucketName=bucket,
            indexName=bad_data_type_name,
            dimension=_DIMENSION,
            distanceMetric="cosine",
            dataType="float16",
        ),
        *_ERR_BAD_DATA_TYPE,
    )

    for refused_name in (bad_metric_name, bad_data_type_name):
        _expect_error(
            lambda n=refused_name: s3v.get_index(vectorBucketName=bucket, indexName=n),
            *_ERR_INDEX_NOT_FOUND,
        )

    listed = {i["indexName"] for i in s3v.list_indexes(vectorBucketName=bucket)["indexes"]}
    assert bad_metric_name not in listed, listed
    assert bad_data_type_name not in listed, listed

    for metric in ("euclidean", "cosine"):
        good_name = ctx.unique_name(f"sim2real-behav-{metric}-")
        s3v.create_index(
            vectorBucketName=bucket,
            indexName=good_name,
            dimension=_DIMENSION,
            distanceMetric=metric,
            dataType="float32",
        )
        ctx.on_cleanup(lambda n=good_name: s3v.delete_index(vectorBucketName=bucket, indexName=n))
        info = s3v.get_index(vectorBucketName=bucket, indexName=good_name)["index"]
        assert info["distanceMetric"] == metric, info


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
