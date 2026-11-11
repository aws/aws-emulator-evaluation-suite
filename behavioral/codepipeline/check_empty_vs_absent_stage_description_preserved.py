"""empty-vs-absent-stage-description-preserved."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "empty-vs-absent-stage-description-preserved"
GROUP = "state-machine"
SERVICES = ["codepipeline"]


# Stage and action declarations have no description field; a pipeline variable's
# description (minimum length 0) is the field where empty and absent differ.
@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An empty-string pipeline-variable description round-trips through Create/Update/
    GetPipeline as a present empty key, distinct from an omitted description, which
    stays absent."""
    cp = ctx.client("codepipeline")
    bucket = _create_artifact_bucket(ctx)
    role_arn = _create_pipeline_role(ctx, bucket)
    source_action = _create_custom_action_type(ctx, "Source", ctx.unique_name("SimSrc").replace("-", ""), output_range=(1, 1))
    build_action = _create_custom_action_type(ctx, "Build", ctx.unique_name("SimBld").replace("-", ""), input_range=(1, 1))

    name = ctx.unique_name("sim2real-cp-")
    pipeline_def = {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "stages": _worker_pipeline_stages(source_action["provider"], build_action["provider"]),
        "variables": [
            {"name": "VarWithEmptyDesc", "defaultValue": "x", "description": ""},
            {"name": "VarNoDesc", "defaultValue": "y"},
        ],
    }
    _create_pipeline(ctx, pipeline_def, tags=[{"key": "sim2real", "value": CHECK}])

    got = cp.get_pipeline(name=name)["pipeline"]
    variables_by_name = {v["name"]: v for v in got["variables"]}

    with_empty = variables_by_name["VarWithEmptyDesc"]
    without = variables_by_name["VarNoDesc"]
    assert "description" in with_empty and with_empty["description"] == ""
    assert "description" not in without

    # Swap which variable has the explicit empty description via UpdatePipeline, and
    # confirm the distinction is preserved (not just defaulted the same way both times).
    got["variables"] = [
        {"name": "VarWithEmptyDesc", "defaultValue": "x"},
        {"name": "VarNoDesc", "defaultValue": "y", "description": ""},
    ]
    updated = cp.update_pipeline(pipeline=got)["pipeline"]
    updated_by_name = {v["name"]: v for v in updated["variables"]}
    assert "description" not in updated_by_name["VarWithEmptyDesc"]
    assert "description" in updated_by_name["VarNoDesc"] and updated_by_name["VarNoDesc"]["description"] == ""

    reread = cp.get_pipeline(name=name)["pipeline"]
    reread_by_name = {v["name"]: v for v in reread["variables"]}
    assert "description" not in reread_by_name["VarWithEmptyDesc"]
    assert reread_by_name["VarNoDesc"]["description"] == ""


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
    # S3's CreateBucket rejects an explicit LocationConstraint of "us-east-1" (it is the
    # implicit default) -- this branches on ctx.region, not a fixed region, so it runs
    # correctly under the suite's actual us-west-2 region and any other.
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
    # No blind wait here: the just-created role's trust policy needs to propagate before
    # CodePipeline can assume it, and that wait is already a bounded retry (not a sleep) in
    # _create_pipeline below, which retries on the specific ValidationException/
    # InvalidStructureException propagation raises until CreatePipeline succeeds or a deadline.
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
