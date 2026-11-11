"""update-pipeline-malformed-declarations-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-pipeline-malformed-declarations-rejected"
GROUP = "error-semantics"
SERVICES = ["codepipeline"]
_SCENARIO = "update-pipeline-malformed-declarations-rejected"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePipeline with a source action on a nonexistent provider fails with InvalidActionDeclarationException
    and its exact message and leaves the pipeline unchanged, while a valid update raises the version by one
    and persists.
    """
    cp = ctx.client("codepipeline")
    bucket = _create_artifact_bucket(ctx)
    key = _put_source_object(ctx, bucket)
    role_arn = _create_pipeline_role(ctx, bucket)
    name = ctx.unique_name("sim2real-cp-upd-")
    stages = [_source_stage(bucket, key), _approval_stage("Gate", "Approve")]
    created = _create_pipeline(ctx, name, role_arn, bucket, stages)
    original_version = created["version"]

    broken = json.loads(json.dumps(created))
    broken["stages"][0]["actions"][0]["actionTypeId"]["provider"] = "NoSuchProviderSim2Real"

    def _bad_update():
        return cp.update_pipeline(pipeline=broken)

    code, message = _error(_bad_update)
    assert code == "InvalidActionDeclarationException", (
        f"expected InvalidActionDeclarationException for a source action pointed at a "
        f"nonexistent provider, got {code!r}"
    )
    region_enum = ctx.region.upper().replace("-", "_")
    expected_message = (
        "ActionType (Category: 'Source', Provider: 'NoSuchProviderSim2Real', Owner: 'AWS', "
        f"Version: '1') in action 'Source' is not available in region '{region_enum}'"
    )
    assert message == expected_message, (
        f"expected the exact rejection message {expected_message!r}, got {message!r}"
    )

    # Effect absent: the pipeline's version and source provider did not change.
    unchanged = cp.get_pipeline(name=name)["pipeline"]
    assert unchanged["version"] == original_version, (
        f"expected version to stay at {original_version} after the rejected update, "
        f"got {unchanged['version']}"
    )
    assert unchanged["stages"][0]["actions"][0]["actionTypeId"]["provider"] == "S3", (
        "expected the source action's provider to remain 'S3' after the rejected update, "
        f"got {unchanged['stages'][0]['actions'][0]['actionTypeId']['provider']!r}"
    )

    # Positive control: a legitimate structural change succeeds and bumps version.
    good = json.loads(json.dumps(created))
    good["stages"][1]["actions"][0]["timeoutInMinutes"] = 10
    resp = cp.update_pipeline(pipeline=good)
    assert resp["pipeline"]["version"] == original_version + 1, (
        f"expected the update response to report version {original_version + 1}, "
        f"got {resp['pipeline']['version']}"
    )

    # Independent read at a different operation than the one that mutated: the version
    # bump and the structural change both persisted server-side, not just in the
    # update call's own echoed response.
    persisted = cp.get_pipeline(name=name)["pipeline"]
    assert persisted["version"] == original_version + 1, (
        f"expected get_pipeline to report the persisted version {original_version + 1}, "
        f"got {persisted['version']}"
    )
    assert persisted["stages"][1]["actions"][0]["timeoutInMinutes"] == 10, (
        "expected the legitimate structural change (timeoutInMinutes=10) to persist, got "
        f"{persisted['stages'][1]['actions'][0].get('timeoutInMinutes')!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("app.txt", b"hello-sim2real")
    return buf.getvalue()


def _create_pipeline_role(ctx, bucket_name: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp-role-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "codepipeline.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:GetObjectVersion",
                        "s3:PutObject",
                        "s3:GetBucketVersioning",
                        "s3:ListBucket",
                    ],
                    "Resource": [
                        f"arn:aws:s3:::{bucket_name}",
                        f"arn:aws:s3:::{bucket_name}/*",
                    ],
                }
            ],
        }
    )
    policy_name = "artifact-access"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=policy_doc)
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]
    return role_arn


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-art-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": _SCENARIO}]})

    def _cleanup():
        versions = s3.list_object_versions(Bucket=bucket)
        objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in versions.get("Versions", [])]
        objs += [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in versions.get("DeleteMarkers", [])]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _put_source_object(ctx, bucket: str, key: str = "source.zip") -> str:
    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key=key, Body=_zip_bytes())
    return key


def _source_stage(bucket: str, key: str) -> dict:
    action = {
        "name": "Source",
        "actionTypeId": {"category": "Source", "owner": "AWS", "provider": "S3", "version": "1"},
        "configuration": {"S3Bucket": bucket, "S3ObjectKey": key, "PollForSourceChanges": "false"},
        "outputArtifacts": [{"name": "SourceOutput"}],
    }
    return {"name": "Source", "actions": [action]}


def _approval_stage(stage_name: str, action_name: str) -> dict:
    return {
        "name": stage_name,
        "actions": [
            {
                "name": action_name,
                "actionTypeId": {"category": "Approval", "owner": "AWS", "provider": "Manual", "version": "1"},
            }
        ],
    }


def _create_pipeline(ctx, name: str, role_arn: str, bucket: str, stages: list, pipeline_type: str = "V2",
                      execution_mode: str = "SUPERSEDED") -> dict:
    cp = ctx.client("codepipeline")
    pipeline = {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "stages": stages,
        "pipelineType": pipeline_type,
        "executionMode": execution_mode,
    }
    # Bounded retry (deadline: 6 attempts x 5s = 30s) for IAM role propagation: a role
    # created moments ago can still make CodePipeline reject it as structurally invalid.
    last_err = None
    resp = None
    for _ in range(6):
        try:
            resp = cp.create_pipeline(pipeline=pipeline, tags=[{"key": "sim2real", "value": _SCENARIO}])
            break
        except ClientError as err:
            last_err = err
            if err.response["Error"]["Code"] in ("InvalidStructureException", "ValidationException"):
                time.sleep(5)
                continue
            raise
    if resp is None:
        raise last_err
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))
    return resp["pipeline"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
