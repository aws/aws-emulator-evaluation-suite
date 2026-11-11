"""put-table-bucket-storage-class-invalid-value-rejected."""
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-table-bucket-storage-class-invalid-value-rejected"
GROUP = "error-semantics"
SERVICES = ["s3tables"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutTableBucketStorageClass with a value outside the StorageClass enum is ValidationException with
    the exact enum-constraint message and leaves the storage class unchanged, while
    INTELLIGENT_TIERING is accepted and returned by GetTableBucketStorageClass."""
    s3tables = ctx.client("s3tables")
    bucket_arn = _create_table_bucket(ctx, s3tables)

    before = s3tables.get_table_bucket_storage_class(tableBucketARN=bucket_arn)[
        "storageClassConfiguration"
    ]

    code, message = _error(
        lambda: s3tables.put_table_bucket_storage_class(
            tableBucketARN=bucket_arn,
            storageClassConfiguration={"storageClass": "ULTRA_FAST_TIER"},
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = (
        "1 validation error detected: Value at 'storageClassConfiguration.storageClass' failed "
        "to satisfy constraint: Member must satisfy enum value set: [INTELLIGENT_TIERING, STANDARD]"
    )
    assert message == expected, f"message={message!r}"

    after = s3tables.get_table_bucket_storage_class(tableBucketARN=bucket_arn)[
        "storageClassConfiguration"
    ]
    assert after == before, f"storage class changed after rejected update: {before} -> {after}"

    # Positive control: a valid enum value is accepted.
    s3tables.put_table_bucket_storage_class(
        tableBucketARN=bucket_arn,
        storageClassConfiguration={"storageClass": "INTELLIGENT_TIERING"},
    )
    updated = s3tables.get_table_bucket_storage_class(tableBucketARN=bucket_arn)[
        "storageClassConfiguration"
    ]
    assert updated["storageClass"] == "INTELLIGENT_TIERING", (
        f"expected storage class INTELLIGENT_TIERING after valid update, got {updated!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a value real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects ULTRA_FAST_TIER as a storage class, but it SUCCEEDED and returned {result!r}"
    )


def _bucket_name(ctx) -> str:
    raw = ctx.unique_name("sim2real-s3t-").lower()
    return re.sub(r"[^0-9a-z-]", "-", raw)[:63]


def _create_table_bucket(ctx, s3tables) -> str:
    name = _bucket_name(ctx)
    arn = s3tables.create_table_bucket(
        name=name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-s3t-"},
    )["arn"]
    ctx.on_cleanup(lambda: s3tables.delete_table_bucket(tableBucketARN=arn))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
