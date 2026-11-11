"""update-pipeline-invalid-action-declaration-rejected."""
from __future__ import annotations

import copy
import json
import time

from behavioral_harness import tags

CHECK = "update-pipeline-invalid-action-declaration-rejected"
GROUP = "error-semantics"
SERVICES = ["codepipeline"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdatePipeline with an Approval action declaring an output artifact fails with
    InvalidActionDeclarationException (not InvalidStructureException), leaves the definition
    unchanged, and a later well-formed update still succeeds."""
    cp = ctx.client("codepipeline")
    bucket = _create_bucket(ctx)
    role_arn = _create_role(ctx)
    name = ctx.unique_name("sim2real-cp-actdecl-")
    stages = [
        {
            "name": "Source",
            "actions": [
                {
                    "name": "SourceAction",
                    "actionTypeId": {
                        "category": "Source",
                        "owner": "AWS",
                        "provider": "S3",
                        "version": "1",
                    },
                    "configuration": {
                        "S3Bucket": bucket,
                        "S3ObjectKey": "source.zip",
                        "PollForSourceChanges": "false",
                    },
                    "outputArtifacts": [{"name": "SourceOutput"}],
                }
            ],
        },
        {
            "name": "Approve",
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
        },
    ]
    original = _create_pipeline(ctx, name, role_arn, bucket, stages)
    original_version = original["pipeline"]["version"]

    broken = copy.deepcopy(original["pipeline"])
    # A Manual approval action accepts zero output artifacts (see "Valid input and
    # output artifacts for each action type" in the CodePipeline user guide);
    # declaring one is a structurally invalid action declaration.
    broken["stages"][1]["actions"][0]["outputArtifacts"] = [{"name": "ApprovalOutput"}]

    code, message = _error(lambda: cp.update_pipeline(pipeline=broken))
    assert code == "InvalidActionDeclarationException", f"unexpected code: {code}"
    assert message == (
        "Action ApprovalAction declares 1 output artifacts which is more than the maximum count (0)"
    ), message

    unchanged = cp.get_pipeline(name=name)["pipeline"]
    assert unchanged["version"] == original_version
    assert not unchanged["stages"][1]["actions"][0].get("outputArtifacts")

    # positive control: a well-formed update on the same pipeline still succeeds and
    # bumps the server-assigned version.
    good = copy.deepcopy(unchanged)
    good["stages"][0]["actions"][0]["configuration"]["S3ObjectKey"] = "source-v2.zip"
    updated = cp.update_pipeline(pipeline=good)["pipeline"]
    assert updated["version"] == original_version + 1

    # terminal read is independent of the mutating update_pipeline call above
    final = cp.get_pipeline(name=name)["pipeline"]
    assert final["version"] == original_version + 1, final["version"]
    assert final["stages"][0]["actions"][0]["configuration"]["S3ObjectKey"] == "source-v2.zip"


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-actdecl-").lower().replace("_", "-")
    # us-east-1 is the one region that rejects an explicit LocationConstraint on
    # CreateBucket; this compares against it to pick the right call shape, it does
    # not pin the check to that region.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        objs = s3.list_object_versions(Bucket=bucket)
        to_delete = [
            {"Key": v["Key"], "VersionId": v["VersionId"]}
            for v in objs.get("Versions", []) + objs.get("DeleteMarkers", [])
        ]
        if to_delete:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": to_delete}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "codepipeline.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    # IAM roles can take a short time to propagate before another service can
    # assume them: https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_general.html#troubleshoot_general_eventual-consistency
    # The remaining propagation lag (role exists but is not yet assumable by
    # codepipeline.amazonaws.com) is absorbed by _create_pipeline's own bounded
    # retry on InvalidStructureException below, not by a flat sleep here.
    deadline = time.monotonic() + 20
    while True:
        if iam.get_role(RoleName=role_name)["Role"]["RoleName"] == role_name:
            break
        if time.monotonic() > deadline:
            raise AssertionError(f"role {role_name} did not become visible to get_role within 20s")
        time.sleep(1)
    return role["Arn"]


def _create_pipeline(ctx, name, role_arn, bucket, stages):
    from botocore.exceptions import ClientError

    cp = ctx.client("codepipeline")
    pipeline = {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "stages": stages,
    }
    deadline = time.monotonic() + 60
    while True:
        try:
            result = cp.create_pipeline(pipeline=pipeline, tags=[{"key": "sim2real", "value": CHECK}])
            break
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidStructureException" or time.monotonic() > deadline:
                raise
            time.sleep(5)
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
