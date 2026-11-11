"""create-model-card-export-job-missing-card-not-found."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-model-card-export-job-missing-card-not-found"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateModelCardExportJob referencing a model card that was never created
    returns ResourceNotFound, and creates no export job as a side effect."""
    sm = ctx.client("sagemaker")
    missing_card_name = ctx.unique_name("sim2real-card-missing-")
    bucket = ctx.unique_name("sim2real-modelcard-bucket-")

    # breaking one thing: a model card name that was never created
    code, message = _error_code_and_message(
        lambda: sm.create_model_card_export_job(
            ModelCardName=missing_card_name,
            ModelCardExportJobName=ctx.unique_name("sim2real-mcej-"),
            OutputConfig={"S3OutputPath": f"s3://{bucket}/exports"},
        )
    )
    assert code == "ResourceNotFound", f"expected ResourceNotFound, got {code!r}"
    expected_message = (
        f"Modelcard arn:aws:sagemaker:{ctx.region}:{ctx.account}:model-card/{missing_card_name} does not exist"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: no export job was recorded against the missing card, not
    # merely that the (never-created) card still doesn't exist
    listed = sm.list_model_card_export_jobs(ModelCardName=missing_card_name).get(
        "ModelCardExportJobSummaries", []
    )
    assert listed == [], f"expected no export jobs for missing card, found {listed}"

    # positive control: a real model card can have an export job created against it
    real_card_name = ctx.unique_name("sim2real-card-real-")
    sm.create_model_card(
        ModelCardName=real_card_name,
        Content=json.dumps({"model_overview": {"model_name": real_card_name}}),
        ModelCardStatus="Draft",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_card(sm, real_card_name))
    real_export_job_name = ctx.unique_name("sim2real-mcej-real-")
    export = sm.create_model_card_export_job(
        ModelCardName=real_card_name,
        ModelCardExportJobName=real_export_job_name,
        OutputConfig={"S3OutputPath": f"s3://{bucket}/exports"},
    )
    assert export["ModelCardExportJobArn"]

    # terminal read: independent read at the destination, not the mutating
    # call's own response
    described = sm.describe_model_card_export_job(
        ModelCardExportJobArn=export["ModelCardExportJobArn"]
    )
    assert described["ModelCardExportJobName"] == real_export_job_name, (
        f"expected {real_export_job_name!r}, got "
        f"{described.get('ModelCardExportJobName')!r}"
    )


def _error_code_and_message(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe_delete_card(sm, name):
    try:
        sm.delete_model_card(ModelCardName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
