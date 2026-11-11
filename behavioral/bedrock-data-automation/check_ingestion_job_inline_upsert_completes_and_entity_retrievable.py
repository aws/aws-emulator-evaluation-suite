"""ingestion-job-inline-upsert-completes-and-entity-retrievable."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "ingestion-job-inline-upsert-completes-and-entity-retrievable"
GROUP = "data-plane"
SERVICES = ["bedrock-data-automation"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """An inline-payload VOCABULARY UPSERT ingestion job reaches COMPLETED and the upserted entity
    becomes retrievable both by direct Get and by List."""
    bda = ctx.client("bedrock-data-automation")
    s3 = ctx.client("s3")
    bucket = _create_output_bucket(ctx, s3)
    library_arn = bda.create_data_automation_library(libraryName=ctx.unique_name("sim2real-lib-"))[
        "libraryArn"
    ]
    ctx.on_cleanup(lambda: bda.delete_data_automation_library(libraryArn=library_arn))

    entity_id = ctx.unique_name("med-en-")
    job_arn = bda.invoke_data_automation_library_ingestion_job(
        libraryArn=library_arn,
        entityType="VOCABULARY",
        operationType="UPSERT",
        inputConfiguration={
            "inlinePayload": {
                "upsertEntitiesInfo": [
                    {
                        "vocabulary": {
                            "entityId": entity_id,
                            "language": "EN",
                            "phrases": [{"text": "paracetamol"}, {"text": "ibuprofen"}],
                        }
                    }
                ]
            }
        },
        outputConfiguration={"s3Uri": f"s3://{bucket}/output/"},
    )["jobArn"]

    status = _poll_until(
        lambda: bda.get_data_automation_library_ingestion_job(libraryArn=library_arn, jobArn=job_arn)["job"][
            "jobStatus"
        ],
        lambda s: s in ("COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED"),
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert status == "COMPLETED", f"expected job to reach COMPLETED, got {status!r}"

    entity = bda.get_data_automation_library_entity(
        libraryArn=library_arn, entityType="VOCABULARY", entityId=entity_id
    )["entity"]["vocabulary"]
    assert entity["entityId"] == entity_id, f"expected entityId {entity_id!r}, got {entity['entityId']!r}"
    phrase_texts = {p["text"] for p in entity["phrases"]}
    assert phrase_texts == {"paracetamol", "ibuprofen"}, (
        f"expected phrases {{'paracetamol', 'ibuprofen'}}, got {phrase_texts!r}"
    )

    listed = bda.list_data_automation_library_entities(libraryArn=library_arn, entityType="VOCABULARY")[
        "entities"
    ]
    listed_ids = {e["vocabulary"]["entityId"] for e in listed}
    assert entity_id in listed_ids, f"expected {entity_id!r} in listed entities, got {listed_ids!r}"


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
