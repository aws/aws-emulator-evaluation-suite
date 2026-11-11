"""update-pipeline-invalid-stage-declaration-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-pipeline-invalid-stage-declaration-rejected"
GROUP = "error-semantics"
SERVICES = ["codepipeline"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePipeline rejects a stage declaration that duplicates an existing stage name with
    InvalidStageDeclarationException, leaves the existing pipeline definition and version
    unchanged, and a legitimate update still applies and bumps the version."""
    cp = ctx.client("codepipeline")
    role_arn = _cp_create_role(ctx)
    bucket = _cp_create_bucket(ctx)
    provider = _cp_create_custom_source_type(ctx)
    pipeline_name = _cp_create_pipeline(ctx, role_arn, bucket, provider)

    original = cp.get_pipeline(name=pipeline_name)["pipeline"]
    assert original["version"] == 1, f"expected a freshly created pipeline at version 1, got {original['version']}"

    bad_pipeline = json.loads(json.dumps(original))
    bad_pipeline.pop("version", None)
    # duplicate the only stage's name -> malformed stage declaration (duplicate stage name)
    bad_pipeline["stages"].append(json.loads(json.dumps(bad_pipeline["stages"][0])))

    code, message = _error(lambda: cp.update_pipeline(pipeline=bad_pipeline))
    assert code == "InvalidStageDeclarationException", f"expected InvalidStageDeclarationException, got {code}"
    assert message == f"Stage name '{bad_pipeline['stages'][0]['name']}' is used more than once", message

    # effect absent: definition and version on record are exactly as before the rejected update
    current = cp.get_pipeline(name=pipeline_name)["pipeline"]
    assert current["version"] == 1, f"rejected update must not bump version, got {current['version']}"
    assert current["stages"] == original["stages"], "rejected update must not change the stored stages"

    # positive control: a legitimate update is accepted and bumps the version
    good_pipeline = json.loads(json.dumps(original))
    good_pipeline.pop("version", None)
    good_pipeline["stages"][0]["actions"][0]["name"] = "SourceActionRenamed"
    cp.update_pipeline(pipeline=good_pipeline)
    updated = cp.get_pipeline(name=pipeline_name)["pipeline"]
    assert updated["version"] == 2, f"expected a legitimate update to bump the version to 2, got {updated['version']}"
    assert updated["stages"][0]["actions"][0]["name"] == "SourceActionRenamed", (
        f"expected the renamed action to persist, got {updated['stages'][0]['actions'][0]['name']!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises rather
    than returning a falsy sentinel."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
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
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: cp.delete_custom_action_type(category="Source", provider=provider, version="1"))
    return provider


def _cp_create_pipeline(ctx, role_arn, bucket, provider, extra_stages=None) -> str:
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
        }
    ]
    if extra_stages:
        stages.extend(extra_stages)
    else:
        # CodePipeline requires a minimum of 2 stages.
        stages.append(
            {
                "name": "Approval",
                "actions": [
                    {
                        "name": "ApprovalAction",
                        "actionTypeId": {
                            "category": "Approval",
                            "owner": "AWS",
                            "provider": "Manual",
                            "version": "1",
                        },
                    }
                ],
            }
        )
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
                tags=[{"key": "sim2real", "value": CHECK}],
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
