"""invoke-async-client-token-idempotent-retry-returns-same-arn."""
from __future__ import annotations

import base64
import uuid

from behavioral_harness import tags

CHECK = "invoke-async-client-token-idempotent-retry-returns-same-arn"
GROUP = "idempotency"
SERVICES = ["bedrock-data-automation-runtime"]

_PROFILE_SUFFIX_BY_REGION = {
    "us-east-1": "us.data-automation-v1",
    "us-west-2": "us.data-automation-v1",
    "us-east-2": "us.data-automation-v1",
    "ca-central-1": "na.data-automation-v1",
    "eu-central-1": "eu.data-automation-v1",
    "eu-west-1": "eu.data-automation-v1",
    "eu-west-2": "eu.data-automation-v1",
    "eu-south-2": "eu.data-automation-v1",
    "ap-south-1": "apac.data-automation-v1",
    "ap-southeast-2": "apac.data-automation-v1",
    "ap-northeast-1": "apac.data-automation-v1",
    "us-gov-west-1": "us-gov.data-automation-v1",
}

_MINIMAL_PNG_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk"
    "+A8AAQUBAScY42YAAAAASUVORK5CYII="
)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """InvokeDataAutomationAsync does not deduplicate on a repeated clientToken: two identical calls both
    succeed with distinct invocationArns, so a target that folds the retry into the first job diverges."""
    bda = ctx.client("bedrock-data-automation-runtime")
    s3 = ctx.client("s3")
    profile_arn = _profile_arn(ctx)
    project_arn = _create_project(ctx)
    _, input_uri, output_uri = _create_input_bucket_and_object(ctx, s3)
    client_token = f"sim2real-{uuid.uuid4().hex}"

    def submit():
        return bda.invoke_data_automation_async(
            inputConfiguration={"s3Uri": input_uri},
            outputConfiguration={"s3Uri": output_uri},
            dataAutomationProfileArn=profile_arn,
            dataAutomationConfiguration={"dataAutomationProjectArn": project_arn},
            clientToken=client_token,
        )["invocationArn"]

    first_arn = submit()
    second_arn = submit()

    assert first_arn.startswith("arn:aws:bedrock:") and second_arn.startswith("arn:aws:bedrock:")
    assert first_arn != second_arn, (
        f"reusing the same clientToken unexpectedly deduplicated into a single "
        f"invocation: {first_arn!r} == {second_arn!r}"
    )

    # Independent read at the destination: GetDataAutomationStatus, not the mutating
    # invoke call's own response. Two distinct ARN strings prove nothing on their own --
    # a target could hand back two fresh-looking ARNs for what is internally one job
    # record. Both ARNs resolving independently is what proves two live, separately
    # tracked jobs actually exist.
    first_status = bda.get_data_automation_status(invocationArn=first_arn)
    second_status = bda.get_data_automation_status(invocationArn=second_arn)
    assert "status" in first_status and "jobSubmissionTime" in first_status, (
        f"first invocationArn {first_arn!r} did not resolve to a tracked job via "
        f"GetDataAutomationStatus: {first_status!r}"
    )
    assert "status" in second_status and "jobSubmissionTime" in second_status, (
        f"second invocationArn {second_arn!r} did not resolve to a tracked job via "
        f"GetDataAutomationStatus -- the retry may have been folded into the first "
        f"job under a fabricated second ARN: {second_status!r}"
    )


def _create_project(ctx):
    ctrl = ctx.client("bedrock-data-automation")
    project_name = ctx.unique_name("sim2real-bda-proj-").replace("_", "-")[:128]
    resp = ctrl.create_data_automation_project(
        projectName=project_name,
        projectStage="LIVE",
        standardOutputConfiguration={},
        tags=[{"key": "sim2real", "value": "invoke-async-client-token-idempotent-retry"}],
    )
    project_arn = resp["projectArn"]
    ctx.on_cleanup(lambda: ctrl.delete_data_automation_project(projectArn=project_arn))
    return project_arn


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _profile_arn(ctx):
    suffix = _PROFILE_SUFFIX_BY_REGION.get(ctx.region)
    if suffix is None:
        raise AssertionError(
            f"region {ctx.region} is not one of the documented BDA cross-region-inference "
            "source regions; cannot construct a data-automation-profile ARN"
        )
    return f"arn:aws:bedrock:{ctx.region}:{_account_id(ctx)}:data-automation-profile/{suffix}"


def _minimal_png_bytes():
    return base64.b64decode(_MINIMAL_PNG_B64)


def _empty_and_delete_bucket(s3, bucket):
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _create_input_bucket_and_object(ctx, s3):
    bucket = ctx.unique_name("sim2real-bda-").replace("_", "-").lower()
    if ctx.region != "us-east-1":
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    else:
        s3.create_bucket(Bucket=bucket)
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "invoke-async-client-token-idempotent-retry"}]},
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    key = "input/asset.png"
    s3.put_object(Bucket=bucket, Key=key, Body=_minimal_png_bytes(), ContentType="image/png")
    return bucket, f"s3://{bucket}/{key}", f"s3://{bucket}/output/"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
