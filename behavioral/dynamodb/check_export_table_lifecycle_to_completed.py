"""export-table-lifecycle-to-completed."""

from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "export-table-lifecycle-to-completed"
GROUP = "state-machine"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ExportTableToPointInTime transitions IN_PROGRESS -> COMPLETED and the export appears
    in both DescribeExport and ListExports throughout."""
    # The harness enforces ONE hard wall-clock budget for the WHOLE check regardless of
    # any individual poll's own timeout_s — a poll timeout bigger than what's left of that budget
    # can never actually be honored; it only guarantees the process gets killed mid-poll with an
    # unhelpful "Check timed out" instead of a clean assertion. Track elapsed time from the start
    # and hand the dominant, unavoidably-async stage (ExportTableToPointInTime reaching a terminal
    # state) whatever of the real budget remains, instead of a static value that outruns the cap.
    start = time.monotonic()

    def _remaining_budget(total: float = 1700.0, floor: float = 30.0) -> float:
        return max(floor, total - (time.monotonic() - start))

    ddb = ctx.client("dynamodb")
    s3 = ctx.client("s3")

    table_name = ctx.unique_name("sim2real-behav-exp-")
    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: _safe_delete_table(ddb, table_name))
    table_desc = _poll_until(
        lambda: ddb.describe_table(TableName=table_name)["Table"],
        lambda table: table["TableStatus"] == "ACTIVE",
        timeout_s=60,
        interval_s=2,
    )
    table_arn = table_desc["TableArn"]

    # Enable PITR as the FIRST action once the table is ACTIVE (rather than folding it into the
    # export-attempt retry loop below) so its "earliest restorable time" gets the maximum head
    # start to become usable while the item write + S3 bucket creation below run, instead of only
    # starting to settle deep into the check's wall-clock budget (the harness enforces ONE hard
    # wall-clock budget for the WHOLE check, and ExportTableToPointInTime's own completion is the
    # dominant cost against it).
    _enable_pitr_with_retry(ddb, table_name)

    ddb.put_item(TableName=table_name, Item={"pk": {"S": "seed"}})

    bucket_name = ctx.unique_name("sim2real-behav-exp-bkt-").lower().replace("_", "-")
    _create_bucket(s3, bucket_name, ctx.region)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_name))

    def _attempt_export() -> dict[str, Any] | None:
        try:
            # ExportType is named explicitly: DescribeExport on real AWS was observed to omit it
            # when the request left it to its FULL_EXPORT default.
            return ddb.export_table_to_point_in_time(
                TableArn=table_arn, S3Bucket=bucket_name, ExportFormat="DYNAMODB_JSON",
                ExportType="FULL_EXPORT",
            )
        except Exception as exc:  # noqa: BLE001
            if _error_code_from_exc(exc) == "PointInTimeRecoveryUnavailableException":
                return None
            raise

    export_resp = _poll_until(
        _attempt_export, lambda resp: resp is not None, timeout_s=90, interval_s=2
    )

    export_arn = export_resp["ExportDescription"]["ExportArn"]
    initial_status = export_resp["ExportDescription"]["ExportStatus"]
    assert initial_status in ("IN_PROGRESS", "COMPLETED"), (
        f"expected IN_PROGRESS or COMPLETED right after ExportTableToPointInTime, got {initial_status!r}"
    )
    export_table_arn = export_resp["ExportDescription"]["TableArn"]
    assert export_table_arn == table_arn, (
        f"expected ExportDescription.TableArn {table_arn!r}, got {export_table_arn!r}"
    )

    listed_arns = _list_export_arns(ddb, table_arn)
    assert export_arn in listed_arns, (
        f"expected {export_arn!r} in ListExports({table_arn!r}), got {listed_arns!r}"
    )

    # A full export (even of a near-empty table) commonly takes DynamoDB a couple of minutes to
    # reach a terminal state — give the dominant, unavoidably-async stage of this check whatever
    # is left of the harness's hard 300s wall-clock budget (a static timeout_s bigger than that
    # remaining budget can never be honored: the harness kills the whole check at 300s regardless,
    # so the poll should use the real remaining time rather than a number that outruns it).
    described = _poll_until(
        lambda: ddb.describe_export(ExportArn=export_arn)["ExportDescription"],
        lambda desc: desc["ExportStatus"] in ("COMPLETED", "FAILED"),
        timeout_s=_remaining_budget(),
        interval_s=5,
    )
    assert described["ExportStatus"] == "COMPLETED", (
        f"expected the export to reach COMPLETED, got {described['ExportStatus']!r}: {described}"
    )
    assert described["ExportType"] == "FULL_EXPORT", (
        f"expected ExportType FULL_EXPORT, got {described['ExportType']!r}"
    )
    assert described["ExportFormat"] == "DYNAMODB_JSON", (
        f"expected ExportFormat DYNAMODB_JSON, got {described['ExportFormat']!r}"
    )

    listed_arns_final = _list_export_arns(ddb, table_arn)
    assert export_arn in listed_arns_final, (
        f"expected {export_arn!r} in ListExports({table_arn!r}) after COMPLETED, got {listed_arns_final!r}"
    )


def _enable_pitr_with_retry(
    ddb: Any, table_name: str, *, timeout_s: float = 60, interval_s: float = 2
) -> None:
    """A just-created table has continuous backups enabling in the background; an
    UpdateContinuousBackups issued too soon is rejected until that settles — retry for a
    bounded time rather than treating that as a hard failure."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ddb.update_continuous_backups(
                TableName=table_name,
                PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": True},
            )
            return
        except Exception as exc:  # noqa: BLE001
            if _error_code_from_exc(
                exc
            ) == "ContinuousBackupsUnavailableException" and (
                time.monotonic() < deadline
            ):
                time.sleep(interval_s)
                continue
            raise


def _create_bucket(s3: Any, bucket_name: str, region: str) -> None:
    # S3's CreateBucket rejects an explicit LocationConstraint of "us-east-1" (it is the
    # implicit default region and must be omitted, not named) — a real API constraint, not an
    # assumption about where this check runs.
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region}
        )


def _empty_and_delete_bucket(s3: Any, bucket_name: str) -> None:
    """Empty and delete the bucket; one already gone is done."""
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket_name):
            objects = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objects:
                failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objects}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket_name)
    except s3.exceptions.NoSuchBucket:
        pass


def _list_export_arns(ddb: Any, table_arn: str) -> list[str]:
    arns: list[str] = []
    kwargs: dict[str, Any] = {"TableArn": table_arn}
    while True:
        resp = ddb.list_exports(**kwargs)
        arns.extend(e["ExportArn"] for e in resp.get("ExportSummaries", []))
        token = resp.get("NextToken")
        if not token:
            return arns
        kwargs["NextToken"] = token


def _safe_delete_table(ddb: Any, table_name: str, timeout_s: float = 240.0) -> None:
    """Delete the table; an absent table is done. A table still CREATING or UPDATING refuses the
    delete with ResourceInUseException, which is retried until *timeout_s*."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ddb.delete_table(TableName=table_name)
            return
        except ddb.exceptions.ResourceNotFoundException:
            return
        except ddb.exceptions.ResourceInUseException:
            if time.monotonic() >= deadline:
                raise
        time.sleep(10)


def _error_code_from_exc(exc: Exception) -> str | None:
    response = getattr(exc, "response", None)
    if not response:
        return None
    return response.get("Error", {}).get("Code")


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float,
    interval_s: float,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
