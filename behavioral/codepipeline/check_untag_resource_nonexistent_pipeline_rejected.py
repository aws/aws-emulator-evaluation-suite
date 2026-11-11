"""untag-resource-nonexistent-pipeline-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "untag-resource-nonexistent-pipeline-rejected"
GROUP = 'tags'
SERVICES = ['codepipeline']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UntagResource on a well-formed ARN naming a nonexistent pipeline fails with
    ResourceNotFoundException and leaves the real pipeline's tag intact; the same call on the
    real pipeline's ARN removes the tag."""
    cp = ctx.client("codepipeline")
    role_arn = _cp_create_role(ctx)
    bucket = _cp_create_bucket(ctx)
    provider = _cp_create_custom_source_type(ctx)
    pipeline = _cp_create_pipeline(ctx, role_arn, bucket, provider)
    real_arn = cp.get_pipeline(name=pipeline)["metadata"]["pipelineArn"]
    bogus_name = pipeline + "-absent"
    bogus_arn = real_arn + "-absent"

    # positive control: TagResource against the real pipeline succeeds, proving the account and
    # credentials are otherwise healthy for this operation family.
    cp.tag_resource(resourceArn=real_arn, tags=[{"key": "Env", "value": "probe"}])
    before = _tag_value(ctx, real_arn, "Env")
    assert before == "probe", f"expected tag Env=probe after TagResource, got {before!r}"

    code, message = _error(lambda: cp.untag_resource(resourceArn=bogus_arn, tagKeys=["Env"]))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    account = real_arn.split(":")[4]
    expected = f"Pipeline with name {bogus_name} does not exist in account {account}."
    assert message == expected, (message, expected)

    # effect absent: the rejected call did not touch the real pipeline's tag
    still = _tag_value(ctx, real_arn, "Env")
    assert still == "probe", f"expected tag Env=probe untouched by rejected call, got {still!r}"

    # the identical operation against the real ARN succeeds
    cp.untag_resource(resourceArn=real_arn, tagKeys=["Env"])
    after = _tag_value(ctx, real_arn, "Env")
    assert after is None, f"expected tag Env removed after UntagResource, got {after!r}"




def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success fails loudly."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("call succeeded; expected a ClientError")


def _tag_value(ctx, resource_arn: str, key: str) -> str | None:
    cp = ctx.client("codepipeline")
    for tag in cp.list_tags_for_resource(resourceArn=resource_arn).get("tags", []):
        if tag["key"] == key:
            return tag["value"]
    return None


def _cp_create_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codepipeline.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "behav-untag-resource-nonexistent-pipeline"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"}]}
    iam.put_role_policy(RoleName=role_name, PolicyName="cp-access", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="cp-access"))
    iam.get_waiter("role_exists").wait(RoleName=role_name, WaiterConfig={"Delay": 2, "MaxAttempts": 10})
    return role_arn


def _cp_create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-art-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "behav-untag-resource-nonexistent-pipeline"}]},
    )
    return bucket


def _cp_create_custom_source_type(ctx) -> str:
    cp = ctx.client("codepipeline")
    provider = ctx.unique_name("cpsrc-")[:25]
    cp.create_custom_action_type(
        category="Source",
        provider=provider,
        version="1",
        inputArtifactDetails={"minimumCount": 0, "maximumCount": 0},
        outputArtifactDetails={"minimumCount": 1, "maximumCount": 1},
    )
    ctx.on_cleanup(lambda: cp.delete_custom_action_type(category="Source", provider=provider, version="1"))
    return provider


def _cp_create_pipeline(ctx, role_arn, bucket, provider) -> str:
    cp = ctx.client("codepipeline")
    name = ctx.unique_name("sim2real-cp-pipe-")
    stages = [
        {
            "name": "Source",
            "actions": [
                {
                    "name": "SourceAction",
                    "actionTypeId": {"category": "Source", "owner": "Custom", "provider": provider, "version": "1"},
                    "outputArtifacts": [{"name": "SourceOutput"}],
                }
            ],
        },
        # CodePipeline requires a minimum of 2 stages.
        {
            "name": "Approval",
            "actions": [
                {
                    "name": "ApprovalAction",
                    "actionTypeId": {"category": "Approval", "owner": "AWS", "provider": "Manual", "version": "1"},
                }
            ],
        },
    ]
    deadline = time.monotonic() + 30
    last_exc = None
    while time.monotonic() < deadline:
        try:
            cp.create_pipeline(
                pipeline={
                    "name": name,
                    "roleArn": role_arn,
                    "artifactStore": {"type": "S3", "location": bucket},
                    "stages": stages,
                },
                tags=[{"key": "sim2real", "value": "behav-untag-resource-nonexistent-pipeline"}],
            )
            break
        except ClientError as exc:
            last_exc = exc
            time.sleep(3)
    else:
        raise last_exc
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
