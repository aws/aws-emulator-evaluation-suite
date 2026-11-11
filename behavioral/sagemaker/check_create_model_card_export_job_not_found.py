"""create-model-card-export-job-not-found."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-model-card-export-job-not-found"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateModelCardExportJob for a nonexistent ModelCardName returns ResourceNotFound and
    records no export job, while a real card exporting to a real S3 bucket succeeds."""
    sm = ctx.client("sagemaker")
    bogus_card_name = ctx.unique_name("sim2real-behav-no-such-card-")
    bucket = _create_bucket(ctx)

    code, message = _error_code_and_message(
        lambda: sm.create_model_card_export_job(
            ModelCardName=bogus_card_name,
            ModelCardExportJobName=ctx.unique_name("sim2real-behav-export-"),
            OutputConfig={"S3OutputPath": f"s3://{bucket}/exports"},
        )
    )
    assert code == "ResourceNotFound", f"expected ResourceNotFound, got {code}"
    expected_message = (
        f"Modelcard arn:aws:sagemaker:{ctx.region}:{ctx.account}:model-card/{bogus_card_name} does not exist"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: no export job exists for a model card that was never created.
    listed = sm.list_model_card_export_jobs(ModelCardName=bogus_card_name).get(
        "ModelCardExportJobSummaries", []
    )
    assert listed == [], f"expected no export jobs, found {listed}"

    # Positive control: a real ModelCard and a real S3 output location succeed.
    card_name = ctx.unique_name("sim2real-behav-card-")
    sm.create_model_card(
        ModelCardName=card_name,
        Content=json.dumps({"model_overview": {"model_description": "ok"}}),
        ModelCardStatus="Draft",
        Tags=[{"Key": "sim2real", "Value": "behavioral-check"}],
    )
    ctx.on_cleanup(lambda: sm.delete_model_card(ModelCardName=card_name))

    job_name = ctx.unique_name("sim2real-behav-export-ok-")
    resp = sm.create_model_card_export_job(
        ModelCardName=card_name,
        ModelCardExportJobName=job_name,
        OutputConfig={"S3OutputPath": f"s3://{bucket}/exports"},
    )
    assert resp["ModelCardExportJobArn"], f"expected an export job ARN, got {resp}"

    listed_ok = sm.list_model_card_export_jobs(ModelCardName=card_name).get(
        "ModelCardExportJobSummaries", []
    )
    assert any(j["ModelCardExportJobName"] == job_name for j in listed_ok), listed_ok


def _error_code_and_message(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-mcexport-")
    # us-east-1 rejects an explicit LocationConstraint for its own region.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "behavioral-check"}]},
    )

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
