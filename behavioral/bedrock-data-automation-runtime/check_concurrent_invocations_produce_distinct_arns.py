"""concurrent-invocations-produce-distinct-arns."""
from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-invocations-produce-distinct-arns"
GROUP = "concurrency"
SERVICES = ["bedrock-data-automation-runtime"]

# Region-pinned by construction: BDA cross-region-inference profile ARNs only exist in
# these documented source regions, each mapped to its own fixed geo-suffix.
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

_CONCURRENCY = 5


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Parallel InvokeDataAutomationAsync calls with the same configuration and no client token
    return one distinct invocationArn per call, and GetDataAutomationStatus resolves each of them as
    its own invocation.
    """
    bda = ctx.client("bedrock-data-automation-runtime")
    s3 = ctx.client("s3")
    profile_arn = _profile_arn(ctx)
    project_arn = _create_project(ctx)
    _, input_uri, output_uri = _create_input_bucket_and_object(ctx, s3)

    def submit(_i):
        return bda.invoke_data_automation_async(
            inputConfiguration={"s3Uri": input_uri},
            outputConfiguration={"s3Uri": output_uri},
            dataAutomationProfileArn=profile_arn,
            dataAutomationConfiguration={"dataAutomationProjectArn": project_arn},
        )["invocationArn"]

    with ThreadPoolExecutor(max_workers=_CONCURRENCY) as pool:
        arns = list(pool.map(submit, range(_CONCURRENCY)))

    assert len(arns) == _CONCURRENCY
    assert len(set(arns)) == _CONCURRENCY, f"expected {_CONCURRENCY} distinct ARNs, got {arns}"
    assert all(a.startswith("arn:aws:bedrock:") for a in arns)

    # Independent read at the destination, through GetDataAutomationStatus rather than
    # the submitting call: each distinct ARN must be a separately trackable invocation,
    # not a collision papered over by returning look-alike strings for one shared job.
    statuses = [bda.get_data_automation_status(invocationArn=a)["status"] for a in arns]
    assert len(statuses) == _CONCURRENCY
    assert all(s in {"Created", "InProgress", "Success", "ServiceError", "ClientError"} for s in statuses), (
        f"expected all {_CONCURRENCY} distinct invocationArns to be independently trackable "
        f"via GetDataAutomationStatus, got statuses {statuses}"
    )


def _create_project(ctx):
    ctrl = ctx.client("bedrock-data-automation")
    project_name = ctx.unique_name("sim2real-bda-proj-").replace("_", "-")[:128]
    resp = ctrl.create_data_automation_project(
        projectName=project_name,
        projectStage="LIVE",
        standardOutputConfiguration={},
        tags=[{"key": "sim2real", "value": "concurrent-invocations-produce-distinct-arns"}],
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
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "concurrent-invocations-produce-distinct-arns"}]})
    key = "input/asset.png"
    s3.put_object(Bucket=bucket, Key=key, Body=_minimal_png_bytes(), ContentType="image/png")
    return bucket, f"s3://{bucket}/{key}", f"s3://{bucket}/output/"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
