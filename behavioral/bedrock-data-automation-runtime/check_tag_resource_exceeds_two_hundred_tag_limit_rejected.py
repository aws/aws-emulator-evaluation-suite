"""tag-resource-exceeds-two-hundred-tag-limit-rejected."""
from __future__ import annotations

import base64

from behavioral_harness import tags

CHECK = "tag-resource-exceeds-two-hundred-tag-limit-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-data-automation-runtime"]

# Region-pinned: BDA cross-region-inference source regions each map to one of four
# geographic profile groups (us/na/eu/apac/us-gov); there is no region-agnostic form.
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After 50 tags on an invocation, a TagResource adding 160 more (210 in total) is refused with
    ServiceQuotaExceededException and the exact limit message, and none of the 160 tags lands.
    """
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

    # Positive control: 50 tags (a conservative in-quota count) succeeds.
    fifty_tags = [{"key": f"sim2real-quota-{i}", "value": "v"} for i in range(50)]
    bda.tag_resource(resourceARN=invocation_arn, tags=fifty_tags)
    tags_at_50 = bda.list_tags_for_resource(resourceARN=invocation_arn)["tags"]
    assert len(tags_at_50) == 50, f"expected 50 tags after positive control, got {len(tags_at_50)}"

    # Negative: pushing well past the per-resource quota in one call is rejected.
    overflow_tags = [{"key": f"sim2real-overflow-{i}", "value": "v"} for i in range(160)]
    code, message = _error_info(lambda: bda.tag_resource(resourceARN=invocation_arn, tags=overflow_tags))
    assert code == "ServiceQuotaExceededException", (
        f"expected ServiceQuotaExceededException for a 210-tag cumulative total, got {code!r}"
    )
    expected_message = (
        "The number of the provided tags is beyond the limit, or the number of total tags "
        "you are trying to attach to the specified resource exceeds the limit."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the resource's tag count is unchanged at 50, and none of the
    # overflow keys landed.
    tags_after_reject = bda.list_tags_for_resource(resourceARN=invocation_arn)["tags"]
    assert len(tags_after_reject) == 50, (
        f"expected tag count unchanged at 50 after rejected overflow, got {len(tags_after_reject)}"
    )
    assert all(not t["key"].startswith("sim2real-overflow-") for t in tags_after_reject), (
        f"an overflow tag landed despite rejection: {tags_after_reject}"
    )


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


def _error_info(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
