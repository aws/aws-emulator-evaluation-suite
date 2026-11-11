"""get-status-invalid-arn-pattern-rejected."""
from __future__ import annotations

import base64

from behavioral_harness import tags

CHECK = "get-status-invalid-arn-pattern-rejected"
GROUP = "error-semantics"
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


_INVOCATION_ARN_PATTERN_MESSAGE = (
    "1 validation error detected: Value at 'invocationArn' failed to satisfy constraint: "
    "Member must satisfy regular expression pattern: "
    "arn:aws(|-cn|-iso|-iso-[a-z]|-us-gov):bedrock:[a-zA-Z0-9-]*:[0-9]{12}:"
    "data-automation-invocation/[a-zA-Z0-9-_]+"
)

@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetDataAutomationStatus rejects a well-formed-but-wrong-resource-type ARN with
    ValidationException, while a valid invocation ARN still resolves successfully."""
    bda = ctx.client("bedrock-data-automation-runtime")
    s3 = ctx.client("s3")
    profile_arn = _profile_arn(ctx)
    project_arn = _create_project(ctx)
    _, input_uri, output_uri = _create_input_bucket_and_object(ctx, s3)

    invocation_arn = bda.invoke_data_automation_async(
        inputConfiguration={"s3Uri": input_uri},
        outputConfiguration={"s3Uri": output_uri},
        dataAutomationProfileArn=profile_arn,
        dataAutomationConfiguration={"dataAutomationProjectArn": project_arn},
    )["invocationArn"]

    # Positive control: the real ARN resolves.
    status = bda.get_data_automation_status(invocationArn=invocation_arn)["status"]
    assert status in {"Created", "InProgress", "Success", "ServiceError", "ClientError"}, (
        f"expected a real invocationArn to resolve to a known status, got {status!r}"
    )

    # Negative: same account/region, but wrong resource-type segment -> pattern violation.
    account = invocation_arn.split(":")[4]
    bogus_arn = f"arn:aws:bedrock:{ctx.region}:{account}:wrong-resource-type/abc123"

    code, message = _error(lambda: bda.get_data_automation_status(invocationArn=bogus_arn))
    assert code == "ValidationException", (
        f"expected ValidationException for a wrong-resource-type invocationArn, got {code!r}"
    )
    assert message == _INVOCATION_ARN_PATTERN_MESSAGE, message


def _create_project(ctx):
    ctrl = ctx.client("bedrock-data-automation")
    project_name = ctx.unique_name("sim2real-bda-proj-").replace("_", "-")[:128]
    resp = ctrl.create_data_automation_project(
        projectName=project_name, projectStage="LIVE", standardOutputConfiguration={}
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
    key = "input/asset.png"
    s3.put_object(Bucket=bucket, Key=key, Body=_minimal_png_bytes(), ContentType="image/png")
    return bucket, f"s3://{bucket}/{key}", f"s3://{bucket}/output/"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
