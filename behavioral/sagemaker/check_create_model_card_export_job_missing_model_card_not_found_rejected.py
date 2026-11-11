"""create-model-card-export-job-missing-model-card-not-found-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "create-model-card-export-job-missing-model-card-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateModelCardExportJob referencing a ModelCardName that does not exist is rejected
    with ResourceNotFound and no export job is created, while the same call against a real
    model card succeeds -- the in-file positive control."""
    sm = ctx.client("sagemaker")

    missing_card_name = ctx.unique_name("sim2real-behav-missing-mc-")
    export_job_name = ctx.unique_name("sim2real-behav-export-")
    code, message = _error_code_and_message(
        lambda: sm.create_model_card_export_job(
            ModelCardName=missing_card_name,
            ModelCardExportJobName=export_job_name,
            OutputConfig={"S3OutputPath": f"s3://sim2real-behav/{export_job_name}"},
        )
    )
    assert code == "ResourceNotFound", f"expected ResourceNotFound, got {code!r}"
    expected_message = (
        f"Modelcard arn:aws:sagemaker:{ctx.region}:{ctx.account}:model-card/{missing_card_name} does not exist"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: no export job was recorded against the missing card -- not
    # merely that the (never-created) card still doesn't exist.
    listed = sm.list_model_card_export_jobs(ModelCardName=missing_card_name).get(
        "ModelCardExportJobSummaries", []
    )
    assert listed == [], f"expected no export jobs for missing card, found {listed}"

    # Positive control: create a real model card, then the export job call succeeds.
    real_card_name = ctx.unique_name("sim2real-behav-mc-")
    content = json.dumps({"model_overview": {"model_creator": "sim2real-behavioral-check"}})
    sm.create_model_card(
        ModelCardName=real_card_name,
        Content=content,
        ModelCardStatus="Draft",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: sm.delete_model_card(ModelCardName=real_card_name))

    real_export_job_name = ctx.unique_name("sim2real-behav-export-ok-")
    export_resp = sm.create_model_card_export_job(
        ModelCardName=real_card_name,
        ModelCardExportJobName=real_export_job_name,
        OutputConfig={"S3OutputPath": f"s3://sim2real-behav/{real_export_job_name}"},
    )
    job_arn = export_resp["ModelCardExportJobArn"]
    assert job_arn

    described = sm.describe_model_card_export_job(ModelCardExportJobArn=job_arn)
    assert described["ModelCardExportJobName"] == real_export_job_name


def _error_code_and_message(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
