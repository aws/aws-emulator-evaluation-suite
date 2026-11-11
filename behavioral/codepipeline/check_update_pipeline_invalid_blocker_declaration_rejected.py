"""update-pipeline-invalid-blocker-declaration-rejected."""
from __future__ import annotations

import copy
import json
import time

from behavioral_harness import tags

CHECK = "update-pipeline-invalid-blocker-declaration-rejected"
GROUP = "error-semantics"
SERVICES = ["codepipeline"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdatePipeline with a blocker type other than Schedule fails with ValidationException and its exact
    message and leaves the pipeline version and blockers unchanged, while a valid update raises the version by
    one.
    """
    cp = ctx.client("codepipeline")
    bucket = _create_bucket(ctx)
    role_arn = _create_role(ctx)
    name = ctx.unique_name("sim2real-cp-blkdecl-")
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
    # "type" on a blocker declaration only accepts the literal value "Schedule"
    # (see the CodePipeline API reference for BlockerDeclaration); any other value
    # is an unsupported/invalid blocker declaration.
    broken["stages"][1]["blockers"] = [{"name": "legacy-blocker", "type": "Unsupported"}]

    code, message = _error(lambda: cp.update_pipeline(pipeline=broken))
    assert code == "ValidationException", f"unexpected code: {code}"
    assert message == (
        "1 validation error detected: Value at 'pipeline.stages.2.member.blockers.1.member.type' "
        "failed to satisfy constraint: Member must satisfy enum value set: [Schedule]"
    ), message

    unchanged = cp.get_pipeline(name=name)["pipeline"]
    assert unchanged["version"] == original_version, (
        f"expected version to stay {original_version}, got {unchanged['version']}"
    )
    unchanged_blockers = unchanged["stages"][1].get("blockers")
    assert not unchanged_blockers, f"expected no blockers on the Approve stage, got {unchanged_blockers!r}"

    # positive control: a well-formed update with no blockers still succeeds.
    good = copy.deepcopy(unchanged)
    good["stages"][0]["actions"][0]["configuration"]["S3ObjectKey"] = "source-v2.zip"
    cp.update_pipeline(pipeline=good)
    # independent read at the destination -- not the mutating call's own response.
    updated = cp.get_pipeline(name=name)["pipeline"]
    assert updated["version"] == original_version + 1, (
        f"expected version {original_version + 1} after the legitimate update, got {updated['version']}"
    )
    updated_key = updated["stages"][0]["actions"][0]["configuration"]["S3ObjectKey"]
    assert updated_key == "source-v2.zip", f"expected updated S3ObjectKey source-v2.zip, got {updated_key!r}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-blkdecl-").lower().replace("_", "-")
    # us-east-1 is the one region S3 CreateBucket rejects a LocationConstraint for;
    # this branches on ctx.region, it does not pin one.
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
    # IAM roles can take a short time to propagate before another service can assume
    # them: https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_general.html#troubleshoot_general_eventual-consistency
    # _create_pipeline below already retries on InvalidStructureException with its own
    # deadline, which absorbs any remaining propagation delay -- no extra blind sleep here.
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if iam.get_role(RoleName=role_name)["Role"]["RoleName"] == role_name:
            break
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
