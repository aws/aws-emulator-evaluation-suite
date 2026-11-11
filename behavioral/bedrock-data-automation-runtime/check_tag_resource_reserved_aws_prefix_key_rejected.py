"""tag-resource-reserved-aws-prefix-key-rejected."""
from __future__ import annotations

import base64

from behavioral_harness import tags

CHECK = "tag-resource-reserved-aws-prefix-key-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-data-automation-runtime"]

# Region-pinned: BDA's cross-region-inference profile suffix is a fixed function of the
# documented source region, not an account setting, so the literal region keys are the contract.
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


_TAG_KEY_PATTERN_MESSAGE = (
    "1 validation error detected: Value at 'tags.1.member.key' failed to satisfy constraint: "
    "Member must satisfy regular expression pattern: "
    r"(?!aws:)[\p{L}\p{Z}\p{N}_.:/=+\-@]*"
)

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource rejects a tag key that starts with the reserved "aws:" prefix with
    ValidationException, leaves the resource's tag set unchanged, while tagging with a
    normal key on the same resource still succeeds (positive control)."""
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

    # Negative: reserved "aws:" prefix on the tag key.
    code, message = _error(
        lambda: bda.tag_resource(
            resourceARN=invocation_arn, tags=[{"key": "aws:reserved", "value": "nope"}]
        )
    )
    assert code == "ValidationException", f"expected ValidationException for aws: prefix key, got {code!r}"
    assert message == _TAG_KEY_PATTERN_MESSAGE, message

    # Effect absent: the rejected tag never landed.
    tags_after_reject = bda.list_tags_for_resource(resourceARN=invocation_arn)["tags"]
    assert all(t["key"] != "aws:reserved" for t in tags_after_reject), (
        f"rejected tag key 'aws:reserved' landed anyway: {tags_after_reject!r}"
    )

    # Positive control: a normal tag key on the same resource succeeds.
    bda.tag_resource(resourceARN=invocation_arn, tags=[{"key": "sim2real-owner", "value": "behavioral"}])
    tags_after_accept = bda.list_tags_for_resource(resourceARN=invocation_arn)["tags"]
    assert any(
        t["key"] == "sim2real-owner" and t["value"] == "behavioral" for t in tags_after_accept
    ), f"positive-control tag 'sim2real-owner' missing after accepted TagResource: {tags_after_accept!r}"


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
