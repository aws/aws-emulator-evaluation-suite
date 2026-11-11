"""pipeline-metadata-unicode-name-round-trip."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "pipeline-metadata-unicode-name-round-trip"
GROUP = "server-side"
SERVICES = ["codepipeline"]

# Stage/action *names* are constrained to ^[A-Za-z0-9.@\-_]+$ by the API (ASCII only), so the
# unicode round trip is exercised on the field that IS free-form text: an action's
# configuration value (ActionConfigurationValue has no pattern restriction, length 1-1000).
_UNICODE_TEXT = "caf\u00e9 \u2014 \u65e5\u672c\u8a9e \U0001f680 \"quoted\" & <tag> \u00e9\u00e8\u00ea"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Unicode action-configuration text survives a CreatePipeline -> UpdatePipeline -> GetPipeline round trip byte-identically."""
    cp = ctx.client("codepipeline")
    bucket = _create_artifact_bucket(ctx)
    role_arn = _create_pipeline_role(ctx, bucket)

    source_provider = ctx.unique_name("sim2real-cp-src-")
    build_provider = ctx.unique_name("sim2real-cp-bld-")
    _create_custom_action_type(ctx, "Source", source_provider, "1", 0, 0, 1, 1)
    _create_custom_action_type(
        ctx, "Build", build_provider, "1", 1, 1, 0, 1,
        config_props=[
            {"name": "Comment", "required": False, "key": False, "secret": False, "type": "String"},
            {"name": "Marker", "required": False, "key": False, "secret": False, "type": "String"},
        ],
    )

    pipeline_name = ctx.unique_name("sim2real-cp-pipe-")

    def _pipeline(build_config):
        return {
            "name": pipeline_name,
            "roleArn": role_arn,
            "artifactStore": {"type": "S3", "location": bucket},
            "stages": [
                {
                    "name": "Source",
                    "actions": [{
                        "name": "SourceAction",
                        "actionTypeId": {"category": "Source", "owner": "Custom", "provider": source_provider, "version": "1"},
                        "outputArtifacts": [{"name": "SourceOutput"}],
                        "configuration": {},
                    }],
                },
                {
                    "name": "Build",
                    "actions": [{
                        "name": "BuildAction",
                        "actionTypeId": {"category": "Build", "owner": "Custom", "provider": build_provider, "version": "1"},
                        "inputArtifacts": [{"name": "SourceOutput"}],
                        "configuration": build_config,
                    }],
                },
            ],
        }

    _create_pipeline_with_retry(cp, _pipeline({"Comment": _UNICODE_TEXT}), tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=pipeline_name))

    fetched = cp.get_pipeline(name=pipeline_name)["pipeline"]
    build_action = _find_action(fetched, "Build", "BuildAction")
    assert build_action["configuration"]["Comment"] == _UNICODE_TEXT

    # Update the pipeline (adding a second config key) while keeping Comment unchanged, then
    # confirm the unicode text is still byte-identical after the round trip.
    cp.update_pipeline(pipeline=_pipeline({"Comment": _UNICODE_TEXT, "Marker": "v2-" + _UNICODE_TEXT}))

    updated = cp.get_pipeline(name=pipeline_name)["pipeline"]
    updated_action = _find_action(updated, "Build", "BuildAction")
    assert updated_action["configuration"]["Comment"] == _UNICODE_TEXT
    assert updated_action["configuration"]["Marker"] == "v2-" + _UNICODE_TEXT
    assert updated["version"] == fetched["version"] + 1


def _create_pipeline_with_retry(cp, pipeline: dict, tags=None, attempts: int = 6, delay_s: float = 5.0) -> dict:
    """CreatePipeline can transiently fail with InvalidStructureException /
    ValidationException while the just-created IAM role's trust policy propagates."""
    from botocore.exceptions import ClientError

    kwargs = {"pipeline": pipeline}
    if tags:
        kwargs["tags"] = tags
    last_err = None
    for _ in range(attempts):
        try:
            return cp.create_pipeline(**kwargs)
        except ClientError as err:
            last_err = err
            if err.response["Error"]["Code"] in ("InvalidStructureException", "ValidationException"):
                time.sleep(delay_s)
                continue
            raise
    raise last_err


def _find_action(pipeline, stage_name, action_name):
    for stage in pipeline["stages"]:
        if stage["name"] == stage_name:
            for action in stage["actions"]:
                if action["name"] == action_name:
                    return action
    raise AssertionError(f"action {stage_name}/{action_name} not found in pipeline structure")


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-art-").lower().replace("_", "-")[:63]
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        resp = s3.list_object_versions(Bucket=bucket)
        objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in resp.get("Versions", [])]
        objs += [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in resp.get("DeleteMarkers", [])]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_pipeline_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp-role-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "codepipeline.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    })
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_doc = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject", "s3:GetBucketVersioning", "s3:GetBucketAcl", "s3:GetBucketLocation", "s3:ListBucket"],
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        }],
    })
    iam.put_role_policy(RoleName=role_name, PolicyName="artifact-access", PolicyDocument=policy_doc)
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="artifact-access"))
    return role["Arn"]


def _create_custom_action_type(ctx, category, provider, version, in_min, in_max, out_min, out_max, config_props=None):
    cp = ctx.client("codepipeline")
    kwargs = {
        "category": category,
        "provider": provider,
        "version": version,
        "inputArtifactDetails": {"minimumCount": in_min, "maximumCount": in_max},
        "outputArtifactDetails": {"minimumCount": out_min, "maximumCount": out_max},
        "tags": [{"key": "sim2real", "value": CHECK}],
    }
    if config_props:
        kwargs["configurationProperties"] = config_props
    cp.create_custom_action_type(**kwargs)
    ctx.on_cleanup(lambda: cp.delete_custom_action_type(category=category, provider=provider, version=version))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
