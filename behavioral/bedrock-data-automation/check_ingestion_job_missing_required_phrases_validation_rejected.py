"""ingestion-job-missing-required-phrases-validation-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.config import Config

CHECK = "ingestion-job-missing-required-phrases-validation-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-data-automation"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A vocabulary upsert without the required phrases, sent past client-side validation, is
    refused by the service with ValidationException ('... must not be null') and creates no entity,
    while the same upsert with phrases completes and the entity reads back with its phrase.
    """
    bda = ctx.client("bedrock-data-automation")
    # parameter_validation=False so the missing-"phrases" request actually reaches the
    # service instead of being rejected locally by botocore against the required trait.
    bda_unvalidated = ctx.client("bedrock-data-automation", config=Config(parameter_validation=False))
    bucket = _create_output_bucket(ctx)
    library_arn = bda.create_data_automation_library(libraryName=ctx.unique_name("sim2real-bda-lib"))[
        "libraryArn"
    ]
    ctx.on_cleanup(lambda: bda.delete_data_automation_library(libraryArn=library_arn))
    bda.tag_resource(resourceARN=library_arn, tags=[{"key": "purpose", "value": "sim2real"}])

    bad_id = ctx.unique_name("bda-missing-phrases").replace("_", "-")[:40]
    code, message = _client_error(
        lambda: bda_unvalidated.invoke_data_automation_library_ingestion_job(
            libraryArn=library_arn,
            entityType="VOCABULARY",
            operationType="UPSERT",
            inputConfiguration={
                "inlinePayload": {"upsertEntitiesInfo": [{"vocabulary": {"entityId": bad_id, "language": "EN"}}]}
            },
            outputConfiguration={"s3Uri": f"s3://{bucket}/out/"},
        )
    )
    assert code == "ValidationException", f"expected ValidationException from the service for a missing 'phrases' field, got {code}"
    assert message == (
        "1 validation error detected: Value at "
        "'inputConfiguration.inlinePayload.upsertEntitiesInfo.1.member.vocabulary.phrases' "
        "failed to satisfy constraint: Member must not be null"
    ), f"unexpected message: {message!r}"

    # Effect absent: no entity was created under the rejected entityId.
    not_found, not_found_message = _client_error(
        lambda: bda.get_data_automation_library_entity(
            libraryArn=library_arn, entityType="VOCABULARY", entityId=bad_id
        )
    )
    assert not_found == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {not_found}"
    assert not_found_message == "The specified entity ID and entity type is not found.", f"unexpected message: {not_found_message!r}"

    # Positive control: an identical call WITH phrases present ingests successfully.
    ok_id = ctx.unique_name("bda-with-phrases").replace("_", "-")[:40]
    job_arn = bda.invoke_data_automation_library_ingestion_job(
        libraryArn=library_arn,
        entityType="VOCABULARY",
        operationType="UPSERT",
        inputConfiguration={
            "inlinePayload": {
                "upsertEntitiesInfo": [
                    {"vocabulary": {"entityId": ok_id, "language": "EN", "phrases": [{"text": "amoxicillin"}]}}
                ]
            }
        },
        outputConfiguration={"s3Uri": f"s3://{bucket}/out/"},
    )["jobArn"]
    status = _poll_until(
        lambda: bda.get_data_automation_library_ingestion_job(libraryArn=library_arn, jobArn=job_arn)["job"][
            "jobStatus"
        ],
        lambda s: s in ("COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED"),
        timeout_s=180.0,
        interval_s=3.0,
    )
    assert status == "COMPLETED", f"expected COMPLETED for the well-formed ingestion job, got {status}"

    # Terminal read, independent of the mutating call: the entity exists at the
    # destination and carries the ingested phrase.
    entity = bda.get_data_automation_library_entity(
        libraryArn=library_arn, entityType="VOCABULARY", entityId=ok_id
    )["entity"]
    assert entity["vocabulary"]["entityId"] == ok_id, f"expected entityId {ok_id}, got {entity}"
    phrases = entity["vocabulary"].get("phrases", [])
    assert any(p.get("text") == "amoxicillin" for p in phrases), f"expected ingested phrase 'amoxicillin', got {phrases}"


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
    """The (code, message) of the ClientError fn raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
