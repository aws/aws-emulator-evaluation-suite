"""list-ingestion-jobs-reflects-invocation."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "list-ingestion-jobs-reflects-invocation"
GROUP = "data-plane"
SERVICES = ["bedrock-data-automation"]
_TAGS = [{"key": "sim2real", "value": CHECK}]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """After InvokeDataAutomationLibraryIngestionJob, ListDataAutomationLibraryIngestionJobs
    surfaces the new job with matching entityType/operationType/jobArn."""
    bda = ctx.client("bedrock-data-automation")
    bucket = _create_output_bucket(ctx)

    lib_name = ctx.unique_name("sim2real-bda-lib")
    library_arn = bda.create_data_automation_library(libraryName=lib_name, tags=_TAGS)["libraryArn"]
    ctx.on_cleanup(lambda: bda.delete_data_automation_library(libraryArn=library_arn))

    entity_id = ctx.unique_name("term").replace("-", "")[:40]
    job_arn = bda.invoke_data_automation_library_ingestion_job(
        libraryArn=library_arn,
        entityType="VOCABULARY",
        operationType="UPSERT",
        inputConfiguration={
            "inlinePayload": {
                "upsertEntitiesInfo": [
                    {"vocabulary": {"entityId": entity_id, "language": "EN", "phrases": [{"text": "x"}]}}
                ]
            }
        },
        outputConfiguration={"s3Uri": f"s3://{bucket}/out/"},
    )["jobArn"]

    found = _poll_until(
        lambda: {
            j["jobArn"]: j
            for j in bda.list_data_automation_library_ingestion_jobs(libraryArn=library_arn)["jobs"]
        },
        lambda jobs: job_arn in jobs,
        timeout_s=60.0,
        interval_s=2.0,
    )
    listed = found[job_arn]
    assert listed["entityType"] == "VOCABULARY", (
        f"expected entityType VOCABULARY reflected in the list entry, got {listed['entityType']!r}"
    )
    assert listed["operationType"] == "UPSERT", (
        f"expected operationType UPSERT reflected in the list entry, got {listed['operationType']!r}"
    )
    # Positive control: a syntactically and semantically valid single-phrase UPSERT must not be
    # reported as FAILED. (A bare membership check against the full LibraryIngestionJobStatus enum
    # would accept any answer and could never fail; asserting non-failure of a known-good invocation
    # is the discriminating claim this check can make without waiting for terminal completion.)
    assert listed["jobStatus"] != "FAILED", (
        f"expected the validly-invoked UPSERT job not to be reported FAILED in the list, got jobStatus={listed['jobStatus']!r}"
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
