"""create-model-card-export-job-missing-card."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-model-card-export-job-missing-card"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateModelCardExportJob for a nonexistent model card fails with ResourceNotFound and the exact
    message and no job exists at that ARN, while the same call for a real card creates a job that
    DescribeModelCardExportJob returns by name."""
    sm = ctx.client("sagemaker")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    missing_card_name = ctx.unique_name("sim2real-nocard-")[:63]
    bad_job_name = ctx.unique_name("sim2real-cardexport-bad-")

    code, message = _error_code_and_message(
        lambda: sm.create_model_card_export_job(
            ModelCardName=missing_card_name,
            ModelCardExportJobName=bad_job_name,
            OutputConfig={"S3OutputPath": "s3://sim2real-nonexistent-bucket/model-card/"},
        )
    )
    assert code == "ResourceNotFound", f"expected ResourceNotFound, got {code!r}"
    expected_message = (
        f"Modelcard arn:aws:sagemaker:{ctx.region}:{account_id}:model-card/{missing_card_name} does not exist"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the rejected job was never persisted. Independent read on the
    # would-be ARN (never the create call's own response) also 404s.
    bad_job_arn = (
        f"arn:aws:sagemaker:{ctx.region}:{account_id}:model-card/"
        f"{missing_card_name}/export-job/{bad_job_name}"
    )
    describe_code, describe_message = _error_code_and_message(
        lambda: sm.describe_model_card_export_job(ModelCardExportJobArn=bad_job_arn)
    )
    assert describe_code == "ResourceNotFound", (
        f"expected ResourceNotFound describing the never-created job, got {describe_code!r}"
    )
    assert describe_message == f"{bad_job_arn} does not exist", (
        f"expected message {bad_job_arn + ' does not exist'!r}, got {describe_message!r}"
    )

    # Positive control, same file: a real model card accepts the export job.
    real_card_name = ctx.unique_name("sim2real-card-")
    content = json.dumps({"model_overview": {"model_description": "sim2real behavioral check"}})
    sm.create_model_card(
        ModelCardName=real_card_name,
        Content=content,
        ModelCardStatus="Draft",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: sm.delete_model_card(ModelCardName=real_card_name))

    good_job_name = ctx.unique_name("sim2real-cardexport-ok-")
    resp = sm.create_model_card_export_job(
        ModelCardName=real_card_name,
        ModelCardExportJobName=good_job_name,
        OutputConfig={"S3OutputPath": "s3://sim2real-nonexistent-bucket/model-card/"},
    )
    good_job_arn = resp["ModelCardExportJobArn"]
    assert good_job_arn, "expected a non-empty ModelCardExportJobArn from a valid create"

    # Terminal assertion is an independent read, not the mutating call's own response.
    described = sm.describe_model_card_export_job(ModelCardExportJobArn=good_job_arn)
    assert described["ModelCardExportJobName"] == good_job_name, (
        f"expected {good_job_name!r} on independent describe, got "
        f"{described.get('ModelCardExportJobName')!r}"
    )
    assert described["Status"] in ("InProgress", "Completed", "Failed"), (
        f"unexpected export job status {described.get('Status')!r}"
    )


def _error_code_and_message(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
