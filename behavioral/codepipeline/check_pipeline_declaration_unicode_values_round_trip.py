"""pipeline-declaration-unicode-values-round-trip."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pipeline-declaration-unicode-values-round-trip"
GROUP = "representation"
SERVICES = ["codepipeline"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Unicode characters supplied in pipeline tag values at CreatePipeline (and added
    later via TagResource) survive byte-for-byte when read back via ListTagsForResource."""
    cp = ctx.client("codepipeline")
    bucket = _create_artifact_bucket(ctx)
    role_arn = _create_pipeline_role(ctx, bucket)
    source_action = _create_custom_action_type(ctx, "Source", ctx.unique_name("SimSrc").replace("-", ""), output_range=(1, 1))
    build_action = _create_custom_action_type(ctx, "Build", ctx.unique_name("SimBld").replace("-", ""), input_range=(1, 1))

    name = ctx.unique_name("sim2real-cp-")
    # Pipeline/stage/action names only allow [A-Za-z0-9.@\-_]+; tag values have no pattern.
    unicode_value = "héllo-世界-Σπ-Ω-日本語"
    pipeline_def = {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "stages": _worker_pipeline_stages(source_action["provider"], build_action["provider"]),
    }
    _create_pipeline(ctx, pipeline_def, tags=[{"key": "sim2real:created-by", "value": unicode_value}])

    got = cp.get_pipeline(name=name)
    pipeline_arn = got["metadata"]["pipelineArn"]

    tags = _list_all_tags(cp, pipeline_arn)
    assert tags["sim2real:created-by"] == unicode_value

    second_value = "additional-üñíçødé-value"
    cp.tag_resource(resourceArn=pipeline_arn, tags=[{"key": "sim2real:second", "value": second_value}])

    tags2 = _list_all_tags(cp, pipeline_arn)
    assert tags2["sim2real:created-by"] == unicode_value
    assert tags2["sim2real:second"] == second_value


def _list_all_tags(cp, resource_arn: str) -> dict[str, str]:
    out: dict[str, str] = {}
    next_token = None
    while True:
        kwargs: dict[str, Any] = {"resourceArn": resource_arn}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = cp.list_tags_for_resource(**kwargs)
        for t in resp.get("tags", []):
            out[t["key"]] = t["value"]
        next_token = resp.get("nextToken")
        if not next_token:
            return out


# ===== helpers =====
_ROLE_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codepipeline.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)


def _bucket_policy_doc(bucket_name: str) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:GetBucketVersioning", "s3:PutObject"],
                    "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
                }
            ],
        }
    )


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-cp-art-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _cleanup():
        resp = s3.list_object_versions(Bucket=name)
        for v in resp.get("Versions", []) + resp.get("DeleteMarkers", []):
            s3.delete_object(Bucket=name, Key=v["Key"], VersionId=v["VersionId"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _create_pipeline_role(ctx, bucket_name: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp-role-")
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_ROLE_TRUST_POLICY)["Role"]
    policy_name = "artifact-access"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=_bucket_policy_doc(bucket_name))

    def _cleanup():
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _create_custom_action_type(ctx, category: str, provider: str, *, input_range=(0, 0), output_range=(0, 0)) -> dict[str, str]:
    cp = ctx.client("codepipeline")
    cp.create_custom_action_type(
        category=category,
        provider=provider,
        version="1",
        inputArtifactDetails={"minimumCount": input_range[0], "maximumCount": input_range[1]},
        outputArtifactDetails={"minimumCount": output_range[0], "maximumCount": output_range[1]},
    )
    ctx.on_cleanup(lambda: cp.delete_custom_action_type(category=category, provider=provider, version="1"))
    return {"category": category, "owner": "Custom", "provider": provider, "version": "1"}


def _worker_pipeline_stages(source_provider: str, build_provider: str) -> list[dict[str, Any]]:
    return [
        {
            "name": "Source",
            "actions": [
                {
                    "name": "Source",
                    "actionTypeId": {"category": "Source", "owner": "Custom", "provider": source_provider, "version": "1"},
                    "outputArtifacts": [{"name": "SourceOutput"}],
                    "configuration": {},
                    "runOrder": 1,
                }
            ],
        },
        {
            "name": "Build",
            "actions": [
                {
                    "name": "Build",
                    "actionTypeId": {"category": "Build", "owner": "Custom", "provider": build_provider, "version": "1"},
                    "inputArtifacts": [{"name": "SourceOutput"}],
                    "configuration": {},
                    "runOrder": 1,
                }
            ],
        },
    ]


def _safe_delete_pipeline(cp, name: str) -> None:
    try:
        cp.delete_pipeline(name=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "PipelineNotFoundException":
            raise


def _create_pipeline(ctx, pipeline_def: dict[str, Any], *, tags=None) -> dict[str, Any]:
    cp = ctx.client("codepipeline")
    kwargs: dict[str, Any] = {"pipeline": pipeline_def}
    if tags is not None:
        kwargs["tags"] = tags
    last_err = None
    resp = None
    for _ in range(6):
        try:
            resp = cp.create_pipeline(**kwargs)
            break
        except ClientError as err:
            last_err = err
            # IAM role trust/permissions can take a few seconds to propagate to CodePipeline;
            # bound the wait to this retry instead of an unconditional sleep after role creation.
            if err.response["Error"]["Code"] in ("InvalidStructureException", "ValidationException"):
                time.sleep(5)
                continue
            raise
    if resp is None:
        raise last_err
    name = pipeline_def["name"]
    ctx.on_cleanup(lambda: _safe_delete_pipeline(cp, name))
    return resp["pipeline"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
