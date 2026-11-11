"""put-table-bucket-storage-class-conflicting-active-tables-blocked."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-table-bucket-storage-class-conflicting-active-tables-blocked"
GROUP = "error-semantics"
SERVICES = ["s3tables"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutTableBucketStorageClass with a value outside the STANDARD/INTELLIGENT_TIERING enum is rejected
    with ValidationException and leaves the default storage class unchanged; a valid change succeeds."""
    s3t = ctx.client("s3tables")
    arn = _create_table_bucket(ctx)
    original = s3t.get_table_bucket_storage_class(tableBucketARN=arn)["storageClassConfiguration"][
        "storageClass"
    ]

    code, message = _error(
        lambda: s3t.put_table_bucket_storage_class(
            tableBucketARN=arn, storageClassConfiguration={"storageClass": "NOT_A_REAL_STORAGE_CLASS"}
        )
    )
    assert code == "ValidationException", f"code={code}"
    expected = (
        "1 validation error detected: Value at 'storageClassConfiguration.storageClass' failed "
        "to satisfy constraint: Member must satisfy enum value set: [INTELLIGENT_TIERING, STANDARD]"
    )
    assert message == expected, f"message={message!r}"

    # Effect absent: the bucket's storage class default is unchanged by the rejected call.
    unchanged = s3t.get_table_bucket_storage_class(tableBucketARN=arn)["storageClassConfiguration"][
        "storageClass"
    ]
    assert unchanged == original, f"storage class changed after rejected update: {original} -> {unchanged}"

    # Positive control: a valid, distinct storage class value still succeeds afterwards.
    new_class = "INTELLIGENT_TIERING" if original != "INTELLIGENT_TIERING" else "STANDARD"
    s3t.put_table_bucket_storage_class(
        tableBucketARN=arn, storageClassConfiguration={"storageClass": new_class}
    )
    updated = s3t.get_table_bucket_storage_class(tableBucketARN=arn)["storageClassConfiguration"][
        "storageClass"
    ]
    assert updated == new_class, f"expected storage class {new_class!r}, got {updated!r}"


_GONE = ("NotFoundException", "NoSuchEntity")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in _GONE:
            raise


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises: a target
    accepting a call real AWS refuses must not read as a mere code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


def _retry_create_table_bucket(
    s3t, name: str, timeout_s: float = 180.0, interval_s: float = 5.0
) -> str:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return s3t.create_table_bucket(
                name=name,
                tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
            )["arn"]
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "BadRequestException" and "more buckets than are allowed" in err.get(
                "Message", ""
            ):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(interval_s)
                continue
            raise


def _create_table_bucket(ctx) -> str:
    s3t = ctx.client("s3tables")
    arn = _retry_create_table_bucket(s3t, ctx.unique_name("sim2real-s3t-bkt-"))
    ctx.on_cleanup(lambda: _safe(lambda: s3t.delete_table_bucket(tableBucketARN=arn)))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
