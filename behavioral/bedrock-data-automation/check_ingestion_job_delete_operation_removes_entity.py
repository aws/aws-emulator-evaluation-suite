"""ingestion-job-delete-operation-removes-entity."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "ingestion-job-delete-operation-removes-entity"
GROUP = "data-plane"
SERVICES = ["bedrock-data-automation"]
_TAGS = [{"key": "sim2real", "value": CHECK}]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An UPSERT ingestion job followed by a DELETE ingestion job for the same entityId removes
    the entity: GetDataAutomationLibraryEntity 404s afterward, and the freed entityId is
    reusable by a subsequent UPSERT."""
    bda = ctx.client("bedrock-data-automation")
    bucket = _create_output_bucket(ctx)

    lib_name = ctx.unique_name("sim2real-bda-lib")
    library_arn = bda.create_data_automation_library(libraryName=lib_name, tags=_TAGS)["libraryArn"]
    ctx.on_cleanup(lambda: bda.delete_data_automation_library(libraryArn=library_arn))

    entity_id = ctx.unique_name("term").replace("-", "")[:40]
    output_cfg = {"s3Uri": f"s3://{bucket}/ingestion-output/"}

    upsert_job_arn = bda.invoke_data_automation_library_ingestion_job(
        libraryArn=library_arn,
        entityType="VOCABULARY",
        operationType="UPSERT",
        inputConfiguration={
            "inlinePayload": {
                "upsertEntitiesInfo": [
                    {"vocabulary": {"entityId": entity_id, "language": "EN", "phrases": [{"text": "naproxen"}]}}
                ]
            }
        },
        outputConfiguration=output_cfg,
    )["jobArn"]
    _poll_until(
        lambda: bda.get_data_automation_library_ingestion_job(libraryArn=library_arn, jobArn=upsert_job_arn)["job"],
        lambda job: job["jobStatus"] in ("COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED"),
        timeout_s=180.0,
        interval_s=3.0,
    )
    # Entity must exist after the UPSERT (positive control before we delete it).
    existing = bda.get_data_automation_library_entity(
        libraryArn=library_arn, entityType="VOCABULARY", entityId=entity_id
    )["entity"]
    assert existing["vocabulary"]["entityId"] == entity_id, (
        f"expected entityId {entity_id!r} after UPSERT, got {existing['vocabulary'].get('entityId')!r}"
    )

    delete_job_arn = bda.invoke_data_automation_library_ingestion_job(
        libraryArn=library_arn,
        entityType="VOCABULARY",
        operationType="DELETE",
        inputConfiguration={"inlinePayload": {"deleteEntitiesInfo": {"entityIds": [entity_id]}}},
        outputConfiguration=output_cfg,
    )["jobArn"]
    delete_job = _poll_until(
        lambda: bda.get_data_automation_library_ingestion_job(libraryArn=library_arn, jobArn=delete_job_arn)["job"],
        lambda job: job["jobStatus"] in ("COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED"),
        timeout_s=180.0,
        interval_s=3.0,
    )
    assert delete_job["jobStatus"] == "COMPLETED", f"unexpected terminal status: {delete_job}"
    assert delete_job["operationType"] == "DELETE", (
        f"expected operationType DELETE on the delete job, got {delete_job['operationType']!r}"
    )

    code, message = _client_error(
        lambda: bda.get_data_automation_library_entity(
            libraryArn=library_arn, entityType="VOCABULARY", entityId=entity_id
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading the deleted entity, got {code!r} ({message})"
    )
    assert message == "The specified entity ID and entity type is not found.", f"unexpected message: {message!r}"

    # The freed entityId must be reusable: a fresh UPSERT with the same id must complete and the
    # entity must become retrievable again (delete frees the identifier, it does not tombstone it).
    reupsert_job_arn = bda.invoke_data_automation_library_ingestion_job(
        libraryArn=library_arn,
        entityType="VOCABULARY",
        operationType="UPSERT",
        inputConfiguration={
            "inlinePayload": {
                "upsertEntitiesInfo": [
                    {"vocabulary": {"entityId": entity_id, "language": "EN", "phrases": [{"text": "ibuprofen"}]}}
                ]
            }
        },
        outputConfiguration=output_cfg,
    )["jobArn"]
    reupsert_job = _poll_until(
        lambda: bda.get_data_automation_library_ingestion_job(libraryArn=library_arn, jobArn=reupsert_job_arn)[
            "job"
        ],
        lambda job: job["jobStatus"] in ("COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED"),
        timeout_s=180.0,
        interval_s=3.0,
    )
    assert reupsert_job["jobStatus"] == "COMPLETED", (
        f"expected the reused entityId's UPSERT to complete, got {reupsert_job}"
    )
    reused = bda.get_data_automation_library_entity(
        libraryArn=library_arn, entityType="VOCABULARY", entityId=entity_id
    )["entity"]
    assert reused["vocabulary"]["entityId"] == entity_id, (
        f"expected the reused entityId {entity_id!r} to be retrievable, got {reused['vocabulary'].get('entityId')!r}"
    )


def _create_output_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    bucket = ctx.unique_name("sim2real-bda-out").lower()
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowBedrockDataAutomationWrite",
                "Effect": "Allow",
                "Principal": {"Service": "bedrock.amazonaws.com"},
                "Action": ["s3:PutObject", "s3:GetObject"],
                "Resource": f"arn:aws:s3:::{bucket}/*",
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            }
        ],
    }
    import json

    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
    return bucket


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never satisfied within {timeout_s}s, last value: {last}")


def _client_error(fn):
    """Call fn(); return its botocore (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
