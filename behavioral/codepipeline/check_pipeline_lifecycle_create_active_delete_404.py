"""pipeline-lifecycle-create-active-delete-404."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pipeline-lifecycle-create-active-delete-404"
GROUP = "state-machine"
SERVICES = ["codepipeline"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePipeline yields an active pipeline visible via GetPipeline; DeletePipeline then
    makes GetPipeline raise PipelineNotFoundException, and a mutating call against the same
    now-dead name is rejected the same way."""
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
    }
    created = _create_pipeline(ctx, pipeline_def, tags=[{"key": "sim2real", "value": CHECK}])
    assert created["name"] == name, f"expected created pipeline name {name!r}, got {created['name']!r}"
    assert created["version"] == 1, f"expected a freshly created pipeline to be version 1, got {created['version']!r}"

    got = cp.get_pipeline(name=name)
    assert got["pipeline"]["name"] == name, f"GetPipeline name mismatch: expected {name!r}, got {got['pipeline']['name']!r}"
    assert len(got["pipeline"]["stages"]) == 2, f"expected 2 stages, got {len(got['pipeline']['stages'])}"
    expected_arn = f"arn:aws:codepipeline:{ctx.region}:{ctx.account}:{name}"
    assert got["metadata"]["pipelineArn"] == expected_arn, (
        f"pipeline ARN must be built from this region, account and name; expected shape "
        f"arn:aws:codepipeline:<region>:<account>:<name>, got {got['metadata']['pipelineArn']!r}"
    )

    updated_def = got["pipeline"]
    updated_def["stages"][1]["actions"][0]["name"] = "BuildRenamed"
    cp.update_pipeline(pipeline=updated_def)
    after_update = cp.get_pipeline(name=name)["pipeline"]
    assert after_update["version"] == 2, (
        f"UpdatePipeline must bump the pipeline to version 2, got {after_update['version']!r}"
    )
    renamed = after_update["stages"][1]["actions"][0]["name"]
    assert renamed == "BuildRenamed", f"GetPipeline must reflect the renamed action, got {renamed!r}"

    cp.delete_pipeline(name=name)

    refusal = _error_code(lambda: cp.get_pipeline(name=name))
    _assert_pipeline_not_found(
        refusal,
        f"Account '{ctx.account}' does not have a pipeline with name '{name}'",
        "GetPipeline after delete",
    )

    listed = _all_pipeline_names(cp)
    assert name not in listed, f"the deleted pipeline is still in ListPipelines ({len(listed)} names)"

    start_refusal = _error_code(lambda: cp.start_pipeline_execution(name=name))
    _assert_pipeline_not_found(
        start_refusal,
        f"Pipeline with name {name} does not exist in account {ctx.account}.",
        "StartPipelineExecution against the deleted pipeline",
    )


def _assert_pipeline_not_found(refusal, expected: str, what: str) -> None:
    """PipelineNotFoundException, HTTP 400, and the exact message naming the pipeline."""
    code, message, status = refusal
    assert code == "PipelineNotFoundException", f"{what}: expected PipelineNotFoundException, got {code!r}"
    assert status == 400, f"{what}: expected HTTP 400, got {status!r}"
    assert message == expected, f"{what}: expected message {expected!r}, got {message!r}"


def _all_pipeline_names(cp) -> list:
    """Every pipeline name ListPipelines returns, across every page."""
    names, kwargs = [], {}
    while True:
        page = cp.list_pipelines(**kwargs)
        names.extend(p["name"] for p in page.get("pipelines") or [])
        token = page.get("nextToken")
        if not token:
            return names
        kwargs = {"nextToken": token}


# ===== helpers =====
_ROLE_TRUST_POLICY = json.dumps(
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


def _bucket_policy_doc(bucket_name: str) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:GetObjectVersion",
                        "s3:GetBucketVersioning",
                        "s3:PutObject",
                    ],
                    "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
                }
            ],
        }
    )


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-cp-art-").lower()
    if ctx.region == "us-east-1":
        # S3 rejects an explicit LocationConstraint for the us-east-1 default region.
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_ROLE_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
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
        tags=[{"key": "sim2real", "value": CHECK}],
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
                # Bounded retry absorbs IAM role/policy propagation lag before CodePipeline
                # can assume the role (up to 6 * 5s = 30s), rather than an unconditional sleep.
                time.sleep(5)
                continue
            raise
    if resp is None:
        raise last_err
    name = pipeline_def["name"]
    ctx.on_cleanup(lambda: _safe_delete_pipeline(cp, name))
    return resp["pipeline"]


def _error_code(fn: Callable[[], Any]):
    """Return (code, message, HTTP status) of the expected refusal; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return (
            err.response["Error"]["Code"],
            err.response["Error"].get("Message"),
            err.response["ResponseMetadata"]["HTTPStatusCode"],
        )
    raise AssertionError(f"expected a refusal, but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
