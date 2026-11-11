"""ingestion-job-invalid-entity-type-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "ingestion-job-invalid-entity-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-data-automation"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """InvokeDataAutomationLibraryIngestionJob with an entityType outside the VOCABULARY enum is
    rejected synchronously with ValidationException and creates no job/entity, while the same
    payload with the valid entityType ingests successfully."""
    bda = ctx.client("bedrock-data-automation")
    s3 = ctx.client("s3")
    bucket = _create_output_bucket(ctx, s3)
    library_arn = bda.create_data_automation_library(
        libraryName=ctx.unique_name("sim2real-lib-"),
        tags=[{"key": "env", "value": "sim2real"}],
    )["libraryArn"]
    ctx.on_cleanup(lambda: bda.delete_data_automation_library(libraryArn=library_arn))

    bad_id = ctx.unique_name("bad-type-")
    code, message = _client_error(
        lambda: bda.invoke_data_automation_library_ingestion_job(
            libraryArn=library_arn,
            entityType="NOT_A_REAL_ENTITY_TYPE",
            operationType="UPSERT",
            inputConfiguration={
                "inlinePayload": {
                    "upsertEntitiesInfo": [
                        {"vocabulary": {"entityId": bad_id, "language": "EN", "phrases": [{"text": "x"}]}}
                    ]
                }
            },
            outputConfiguration={"s3Uri": f"s3://{bucket}/output/"},
        )
    )
    assert code == "ValidationException", f"unexpected rejection code: {code} ({message})"
    assert message == (
        "1 validation error detected: Value at 'entityType' failed to satisfy constraint: "
        "Member must satisfy enum value set: [VOCABULARY, RECOGNIZED_PERSON]"
    ), f"unexpected message: {message!r}"

    # Effect absent: no entity was ever created under the rejected entityId.
    not_found, not_found_message = _client_error(
        lambda: bda.get_data_automation_library_entity(
            libraryArn=library_arn, entityType="VOCABULARY", entityId=bad_id
        )
    )
    assert not_found == "ResourceNotFoundException", f"rejected entityId should not exist: {not_found}"
    assert not_found_message == "The specified entity ID and entity type is not found.", f"unexpected message: {not_found_message!r}"

    # Positive control: the identical payload with a valid entityType ingests successfully.
    ok_id = ctx.unique_name("ok-phrases-")
    ok_job_arn = bda.invoke_data_automation_library_ingestion_job(
        libraryArn=library_arn,
        entityType="VOCABULARY",
        operationType="UPSERT",
        inputConfiguration={
            "inlinePayload": {
                "upsertEntitiesInfo": [
                    {"vocabulary": {"entityId": ok_id, "language": "EN", "phrases": [{"text": "paracetamol"}]}}
                ]
            }
        },
        outputConfiguration={"s3Uri": f"s3://{bucket}/output/"},
    )["jobArn"]
    ok_status = _poll_until(
        lambda: bda.get_data_automation_library_ingestion_job(libraryArn=library_arn, jobArn=ok_job_arn)["job"][
            "jobStatus"
        ],
        lambda s: s in ("COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED"),
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert ok_status == "COMPLETED", f"positive control did not complete: {ok_status}"


def _create_output_bucket(ctx, s3) -> str:
    bucket = ctx.unique_name("sim2real-bda-out-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    return bucket


def _delete_bucket(s3, bucket: str) -> None:
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objs:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": objs})
    finally:
        s3.delete_bucket(Bucket=bucket)


def _client_error(fn):
    """Call fn(); return its botocore (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() <= deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

