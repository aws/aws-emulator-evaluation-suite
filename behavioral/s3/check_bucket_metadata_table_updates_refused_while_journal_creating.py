"""bucket-metadata-table-updates-refused-while-journal-creating."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bucket-metadata-table-updates-refused-while-journal-creating"
GROUP = "state-machine"
SERVICES = ["s3"]

#: Fresh buckets tried before the check gives up on observing the CREATING window.
_ATTEMPTS = 3
#: Wall bound on all attempts; the runner's remaining time bounds it further.
_DEADLINE_S = 120.0
_BEING_CREATED = (
    "InvalidRequest",
    "You can't perform this operation while the journal table is being created. Wait for your "
    "journal table status to transition to ACTIVE, and then try again.",
)
_REFUSALS = {
    "UpdateBucketMetadataJournalTableConfiguration": (
        "InvalidRequest",
        "You can't perform this operation on a journal table that doesn't have an ACTIVE status. "
        "Wait for your journal table status to transition to ACTIVE, and then try again. If "
        "creation of the journal table fails, you must re-create the metadata configuration for "
        "your general purpose bucket.",
    ),
    "UpdateBucketMetadataInventoryTableConfiguration": _BEING_CREATED,
    "UpdateBucketMetadataAnnotationTableConfiguration": _BEING_CREATED,
}

#: The code _outcome reports for a call the target accepted.
_ACCEPTED = "accepted"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """While a bucket's metadata journal table is CREATING, updating the journal, inventory or
    annotation table configuration is refused with InvalidRequest and the configuration keeps its
    requested journal expiration."""
    s3 = ctx.client("s3")
    deadline = time.monotonic() + _bound(ctx, _DEADLINE_S)
    calls = {
        "UpdateBucketMetadataJournalTableConfiguration": lambda b: (
            s3.update_bucket_metadata_journal_table_configuration(
                Bucket=b,
                JournalTableConfiguration={"RecordExpiration": {"Expiration": "ENABLED", "Days": 14}},
            )
        ),
        "UpdateBucketMetadataInventoryTableConfiguration": lambda b: (
            s3.update_bucket_metadata_inventory_table_configuration(
                Bucket=b, InventoryTableConfiguration={"ConfigurationState": "ENABLED"}
            )
        ),
        "UpdateBucketMetadataAnnotationTableConfiguration": lambda b: (
            s3.update_bucket_metadata_annotation_table_configuration(
                Bucket=b, AnnotationTableConfiguration={"ConfigurationState": "DISABLED"}
            )
        ),
    }
    pending = list(calls)
    tried = []
    for _ in range(_ATTEMPTS):
        if not pending or time.monotonic() >= deadline:
            break
        bucket = ctx.unique_name("sim2real-metacreating-")
        _create_bucket(ctx, s3, bucket)
        s3.create_bucket_metadata_configuration(
            Bucket=bucket,
            MetadataConfiguration={
                "JournalTableConfiguration": {"RecordExpiration": {"Expiration": "ENABLED", "Days": 7}}
            },
        )
        for op in list(pending):
            journal = _journal(s3, bucket)
            if journal["TableStatus"] != "CREATING":
                tried.append(f"{bucket}: journal {journal['TableStatus']} before {op}")
                break
            code, message = _outcome(lambda: calls[op](bucket))
            if (code, message) == _REFUSALS[op]:
                after = _journal(s3, bucket)
                assert after["RecordExpiration"] == {"Expiration": "ENABLED", "Days": 7}, (
                    f"the refused {op} changed the journal expiration: {after['RecordExpiration']!r}"
                )
                pending.remove(op)
                continue
            still = _journal(s3, bucket)["TableStatus"]
            assert still != "CREATING", (
                f"{op} while the journal table stayed CREATING answered {code!r} {message!r}, "
                f"expected {_REFUSALS[op]!r}"
            )
            assert code == _ACCEPTED, (
                f"{op} answered {code!r} {message!r} once the journal table was {still!r}"
            )
            tried.append(f"{bucket}: {op} answered {code!r} after the journal left CREATING ({still!r})")
            break
    assert not pending, (
        f"never observed the refusal of {pending} while the journal table was CREATING in "
        f"{_ATTEMPTS} fresh buckets: {tried!r}"
    )


def _journal(s3, bucket: str) -> dict:
    result = s3.get_bucket_metadata_configuration(Bucket=bucket)
    return result["GetBucketMetadataConfigurationResult"]["MetadataConfigurationResult"][
        "JournalTableConfigurationResult"
    ]


def _outcome(fn) -> tuple[str, str | None]:
    """(code, message) of the refusal ``fn`` raises, or (_ACCEPTED, the response) when it is accepted."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    return _ACCEPTED, repr(result)


def _create_bucket(ctx, s3, bucket: str) -> None:
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":  # us-east-1 takes no LocationConstraint
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    ctx.on_cleanup(lambda: _delete_metadata_tables(ctx, bucket))
    ctx.on_cleanup(lambda: _safe_delete_configuration(s3, bucket))


def _safe_delete_configuration(s3, bucket: str, timeout_s: float = 300.0) -> None:
    """Delete the configuration once its journal table has settled, so the table it leaves is
    listed when the tables are deleted."""
    deadline = time.monotonic() + timeout_s
    try:
        while _journal(s3, bucket)["TableStatus"] == "CREATING":
            if time.monotonic() >= deadline:
                raise AssertionError(f"journal table of {bucket} stayed CREATING for {timeout_s}s")
            time.sleep(5)
        s3.delete_bucket_metadata_configuration(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "MetadataConfigurationNotFound":
            raise


def _delete_metadata_tables(ctx, bucket: str) -> None:
    """Delete the tables, and their namespace, that the configuration leaves in the account's
    AWS-managed table bucket: deleting the configuration or the bucket keeps them, and they bill."""
    tables = ctx.client("s3tables")
    arn = f"arn:aws:s3tables:{ctx.region}:{ctx.account}:bucket/aws-s3"
    namespace = f"b_{bucket}"
    try:
        for page in tables.get_paginator("list_tables").paginate(tableBucketARN=arn, namespace=namespace):
            for table in page.get("tables", []):
                tables.delete_table(tableBucketARN=arn, namespace=namespace, name=table["name"])
        tables.delete_namespace(tableBucketARN=arn, namespace=namespace)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise


def _bound(ctx, cap_s: float) -> float:
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 30.0))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
