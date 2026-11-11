"""ota-task-lifecycle-and-target-validation."""
from __future__ import annotations

import json
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ota-task-lifecycle-and-target-validation"
GROUP = "error-semantics"
SERVICES = ["iot-managed-integrations"]

# iot-managed-integrations is offered only in a few Regions, so the service client and the job
# document bucket are pinned to one of them.
REGION = "eu-west-1"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateOtaTask naming a managed-thing ARN that does not exist is refused and creates no task.

    The refusal is ResourceNotFoundException "ManagedThing record does not exist".
    """
    iot = ctx.client("iot-managed-integrations", region=REGION)
    _ensure_custom_endpoint(iot)
    partition = ctx.client("sts").get_caller_identity()["Arn"].split(":")[1]
    job_document_url = _job_document(ctx, partition)
    missing_target = (
        f"arn:{partition}:iotmanagedintegrations:{REGION}:{ctx.account}"
        f":managed-thing/{uuid.uuid4().hex}"
    )

    before = _task_ids(iot)
    try:
        created = iot.create_ota_task(
            S3Url=job_document_url,
            OtaType="ONE_TIME",
            Target=[missing_target],
            Tags={"sim2real": CHECK},
        )
    except ClientError as e:
        code, message = e.response["Error"]["Code"], e.response["Error"].get("Message")
    else:
        ctx.on_cleanup(lambda: iot.delete_ota_task(Identifier=created["TaskId"]))
        raise AssertionError(
            "expected ResourceNotFoundException for a managed-thing ARN that does not exist, "
            f"got task {created['TaskId']}"
        )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == "ManagedThing record does not exist", (
        f"expected 'ManagedThing record does not exist', got {message!r}"
    )

    created_ids = _task_ids(iot) - before
    assert not created_ids, f"expected no new OTA task after the refusal, got {sorted(created_ids)}"


def _task_ids(iot) -> set[str]:
    pages = iot.get_paginator("list_ota_tasks").paginate()
    return {task["TaskId"] for page in pages for task in page["Tasks"]}


def _ensure_custom_endpoint(iot) -> None:
    """Register the custom endpoint OTA requires; it is account state with no deregister call.

    The model lists ConflictException for RegisterCustomEndpoint, so an already registered
    endpoint is accepted either way.
    """
    try:
        iot.register_custom_endpoint()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ConflictException":
            raise


def _job_document(ctx, partition: str) -> str:
    """An S3 URL to a JSON OTA job document in a bucket the service may read."""
    s3 = ctx.client("s3", region=REGION)
    bucket = ctx.unique_name("sim2real-ota-")
    s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": REGION})
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    s3.put_bucket_policy(
        Bucket=bucket,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "iotmanagedintegrations.amazonaws.com"},
                        "Action": "s3:GetObject",
                        "Resource": f"arn:{partition}:s3:::{bucket}/*",
                        "Condition": {"StringEquals": {"aws:SourceAccount": ctx.account}},
                    }
                ],
            }
        ),
    )
    key = "ota-job-document.json"
    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=json.dumps({"operation": "ota", "version": "1.0.0"}).encode(),
        ContentType="application/json",
    )
    return f"s3://{bucket}/{key}"


def _delete_bucket(s3, bucket: str) -> None:
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
