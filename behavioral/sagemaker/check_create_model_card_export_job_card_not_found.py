"""create-model-card-export-job-card-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-model-card-export-job-card-not-found"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateModelCardExportJob for a never-created version of a real card fails with
    ResourceNotFound and persists no job, while exporting the real version 1 succeeds."""
    sm = ctx.client("sagemaker")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-mcexport-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-owner", "Value": "behavioral-suite"}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    card_name = ctx.unique_name("sim2real-modelcard-")
    content = json.dumps({"model_overview": {"model_creator": "sim2real-behavioral"}})
    sm.create_model_card(
        ModelCardName=card_name,
        Content=content,
        ModelCardStatus="Draft",
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
    )
    ctx.on_cleanup(lambda: sm.delete_model_card(ModelCardName=card_name))

    output_config = {"S3OutputPath": f"s3://{bucket}/exports/"}

    ok_job_name = ctx.unique_name("sim2real-mcexport-ok-")
    ok_job_arn = sm.create_model_card_export_job(
        ModelCardName=card_name,
        ModelCardExportJobName=ok_job_name,
        ModelCardVersion=1,
        OutputConfig=output_config,
    )["ModelCardExportJobArn"]
    # The export writes into the bucket asynchronously; it must settle before the bucket
    # (registered earlier, so emptied and deleted later) is torn down.
    ctx.on_cleanup(lambda: _wait_export_job_settled(sm, ok_job_arn))
    described = sm.describe_model_card_export_job(ModelCardExportJobArn=ok_job_arn)
    assert described["ModelCardName"] == card_name, (
        f"expected the export job to echo model card {card_name!r}, got {described.get('ModelCardName')!r}"
    )
    assert described["ModelCardVersion"] == 1, (
        f"expected the export job to record ModelCardVersion=1, got {described.get('ModelCardVersion')!r}"
    )

    bad_job_name = ctx.unique_name("sim2real-mcexport-bad-")
    code, message = _error_code_and_message(
        lambda: sm.create_model_card_export_job(
            ModelCardName=card_name,
            ModelCardExportJobName=bad_job_name,
            ModelCardVersion=999,
            OutputConfig=output_config,
        )
    )
    assert code == "ResourceNotFound", f"expected ResourceNotFound for a nonexistent card version, got {code!r}"
    # The refusal names the card ARN alone, not the missing version.
    expected_message = (
        f"Modelcard arn:aws:sagemaker:{ctx.region}:{ctx.account}:model-card/{card_name} does not exist"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The rejected job was never persisted: its would-be ARN also 404s on Describe.
    bad_job_arn = ok_job_arn.rsplit("/", 1)[0] + "/" + bad_job_name
    describe_code, describe_message = _error_code_and_message(
        lambda: sm.describe_model_card_export_job(ModelCardExportJobArn=bad_job_arn)
    )
    assert describe_code == "ResourceNotFound", (
        f"expected the rejected export job to remain undescribable (ResourceNotFound), got {describe_code!r}"
    )
    assert describe_message == f"{bad_job_arn} does not exist", (
        f"expected message {bad_job_arn + ' does not exist'!r}, got {describe_message!r}"
    )


def _error_code_and_message(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _wait_export_job_settled(sm, job_arn, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while True:
        status = sm.describe_model_card_export_job(ModelCardExportJobArn=job_arn)["Status"]
        if status != "InProgress":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"export job {job_arn} still InProgress after {timeout_s}s")
        time.sleep(interval_s)


def _empty_and_delete_bucket(s3, bucket):
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
