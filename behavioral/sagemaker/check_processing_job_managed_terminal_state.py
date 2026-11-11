"""processing-job-managed-terminal-state."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "processing-job-managed-terminal-state"
GROUP = "server-side"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """CreateProcessingJob reaches a terminal Completed status that is computed
    entirely server-side (instance provisioning, container run, exit-code
    interpretation, shutdown) without any further client calls."""
    image_uri = _xgboost_image_uri(ctx)
    role_arn = _create_sagemaker_role(ctx)

    sm = ctx.client("sagemaker")
    job_name = ctx.unique_name("sagemaker-sim2real-proc-")
    ctx.on_cleanup(lambda: _ignore(lambda: sm.delete_processing_job(ProcessingJobName=job_name)))

    _create_processing_job_with_role_retry(
        sm,
        ProcessingJobName=job_name,
        RoleArn=role_arn,
        AppSpecification={
            "ImageUri": image_uri,
            "ContainerEntrypoint": ["/bin/sh", "-c"],
            "ContainerArguments": ["exit 0"],
        },
        ProcessingResources={
            "ClusterConfig": {
                "InstanceType": "ml.m5.large",
                "InstanceCount": 1,
                "VolumeSizeInGB": 5,
            }
        },
        StoppingCondition={"MaxRuntimeInSeconds": 900},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )

    initial = sm.describe_processing_job(ProcessingJobName=job_name)
    assert initial["ProcessingJobStatus"] == "InProgress", (
        f"expected freshly-created processing job to start InProgress, got "
        f"{initial['ProcessingJobStatus']}"
    )

    final = _poll_until_terminal(
        lambda: sm.describe_processing_job(ProcessingJobName=job_name),
        status_key="ProcessingJobStatus",
        terminal={"Completed", "Failed", "Stopped"},
        timeout_s=900,
        interval_s=15,
    )

    assert final["ProcessingJobStatus"] == "Completed", (
        f"expected the trivial (exit 0) processing job to complete, got "
        f"{final['ProcessingJobStatus']} ({final.get('FailureReason')})"
    )
    # the service, not the client, populated these as it drove the job to completion
    assert "ProcessingStartTime" in final and "ProcessingEndTime" in final, (
        f"expected the service to have populated both start and end times on a "
        f"Completed job, got keys {sorted(final.keys())}"
    )
    assert final["ProcessingEndTime"] >= final["ProcessingStartTime"], (
        f"expected ProcessingEndTime ({final['ProcessingEndTime']}) >= "
        f"ProcessingStartTime ({final['ProcessingStartTime']})"
    )


#: SageMaker's built-in XGBoost image lives in a distinct ECR registry account per region. These are
#: the `sagemaker` PyPI SDK's OWN values (sagemaker 2.257.6,
#: ``sagemaker/image_uri_config/xgboost.json``, training+inference, versions 1.5-1 and 1.7-1 -- the
#: registry map is identical across those versions), so this is a transcription of the table
#: ``image_uris.retrieve`` reads, not a guess. It is inlined because pulling that SDK in just to
#: read a static JSON map costs torch + CUDA + mlflow and downgrades protobuf and
#: antlr4-python3-runtime in the runner.
_XGB_REGISTRY_ACCOUNTS = {
    "us-east-1": "683313688378",
    "us-east-2": "257758044811",
    "us-west-1": "746614075791",
    "us-west-2": "246618743249",
    "ap-northeast-1": "354813040037",
    "ap-northeast-2": "366743142698",
    "ap-south-1": "720646828776",
    "ap-southeast-1": "121021644041",
    "ap-southeast-2": "783357654285",
    "ca-central-1": "341280168497",
    "eu-central-1": "492215442770",
    "eu-north-1": "662702820516",
    "eu-west-1": "141502667606",
    "eu-west-2": "764974769150",
    "eu-west-3": "659782779980",
    "sa-east-1": "737474898029",
}


def _xgboost_image_uri(ctx) -> str:
    region = ctx.region
    account = _XGB_REGISTRY_ACCOUNTS.get(region)
    if account is None:
        raise AssertionError(
            f"no SageMaker built-in XGBoost ECR registry account mapped for region {region!r} "
            "- add it from the SDK's image_uri_config/xgboost.json to close this gap"
        )
    return f"{account}.dkr.ecr.{region}.amazonaws.com/sagemaker-xgboost:1.7-1"


def _create_sagemaker_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sagemaker-sim2real-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sagemaker.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_sagemaker_role(ctx, role_name))
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess",
    )
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _delete_sagemaker_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.detach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_processing_job_with_role_retry(sm, **kwargs):
    deadline = time.monotonic() + 90
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return sm.create_processing_job(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("AccessDeniedException", "ValidationException") and "assume" in str(exc).lower():
                last_exc = exc
                time.sleep(2)
                continue
            raise
    raise last_exc


def _poll_until_terminal(probe, status_key, terminal, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if last[status_key] in terminal:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"job never reached a terminal state within {timeout_s}s (last status: "
        f"{last[status_key] if last else 'unknown'})"
    )


def _ignore(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
