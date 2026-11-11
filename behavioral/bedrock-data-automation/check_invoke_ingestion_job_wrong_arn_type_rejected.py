"""invoke-ingestion-job-wrong-arn-type-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "invoke-ingestion-job-wrong-arn-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-data-automation"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """InvokeDataAutomationLibraryIngestionJob rejects a syntactically valid ARN of the wrong resource
    type (a Blueprint ARN passed as libraryArn) with ValidationException and creates no entity, while
    the same call against a real Library ARN succeeds and completes."""
    bda = ctx.client("bedrock-data-automation")
    s3 = ctx.client("s3")
    bucket = _create_output_bucket(ctx, s3)
    tag_list = [{"key": "simparity-check", "value": CHECK}]

    blueprint_arn = bda.create_blueprint(
        blueprintName=ctx.unique_name("sim2real-bp-"),
        type="DOCUMENT",
        schema=_blueprint_schema(),
        tags=tag_list,
    )["blueprint"]["blueprintArn"]
    ctx.on_cleanup(lambda: bda.delete_blueprint(blueprintArn=blueprint_arn))

    library_arn = bda.create_data_automation_library(
        libraryName=ctx.unique_name("sim2real-lib-"), tags=tag_list
    )["libraryArn"]
    ctx.on_cleanup(lambda: bda.delete_data_automation_library(libraryArn=library_arn))

    def _invoke(target_arn: str, entity_id: str):
        return bda.invoke_data_automation_library_ingestion_job(
            libraryArn=target_arn,
            entityType="VOCABULARY",
            operationType="UPSERT",
            inputConfiguration={
                "inlinePayload": {
                    "upsertEntitiesInfo": [
                        {"vocabulary": {"entityId": entity_id, "language": "EN", "phrases": [{"text": "test"}]}}
                    ]
                }
            },
            outputConfiguration={"s3Uri": f"s3://{bucket}/output/"},
        )

    bad_entity_id = ctx.unique_name("wrong-type-")
    code, message = _client_error(lambda: _invoke(blueprint_arn, bad_entity_id))
    assert code == "ValidationException", f"expected ValidationException for a blueprint-typed ARN, got {code!r}"
    assert message == (
        "1 validation error detected: Value at 'libraryArn' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: "
        "arn:aws(|-cn|-iso|-iso-[a-z]|-us-gov):bedrock:[a-zA-Z0-9-]*:[0-9]{12}:"
        "data-automation-library/[a-zA-Z0-9-]{12,36}"
    ), f"unexpected message: {message!r}"

    # Effect absent: no entity was ever created under the rejected entityId, in the only real library.
    not_found, not_found_message = _client_error(
        lambda: bda.get_data_automation_library_entity(
            libraryArn=library_arn, entityType="VOCABULARY", entityId=bad_entity_id
        )
    )
    assert not_found == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for the never-created entity, got {not_found!r}"
    )
    assert not_found_message == "The specified entity ID and entity type is not found.", f"unexpected message: {not_found_message!r}"

    # Positive control: the identical call shape against the real Library ARN is accepted and completes.
    ok_entity_id = ctx.unique_name("right-type-")
    job_arn = _invoke(library_arn, ok_entity_id)["jobArn"]
    status = _poll_until(
        lambda: bda.get_data_automation_library_ingestion_job(libraryArn=library_arn, jobArn=job_arn)["job"][
            "jobStatus"
        ],
        lambda s: s in ("COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED"),
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert status == "COMPLETED", f"expected the valid-ARN control job to reach COMPLETED, got {status!r}"


def _blueprint_schema(class_name: str = "SimparityTestDoc", field: str = "test_field") -> str:
    return json.dumps(
        {
            "class": class_name,
            "description": "Simparity behavioral fidelity test blueprint",
            "properties": {
                field: {
                    "type": "string",
                    "inferenceType": "explicit",
                    "instruction": "Extract the test field value",
                }
            },
        }
    )


def _create_output_bucket(ctx, s3) -> str:
    bucket = ctx.unique_name("sim2real-bda-out-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "simparity-check", "Value": CHECK}]})
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
    """Call fn(); return its ClientError (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


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
