"""pipeline-version-integer-persists-across-update."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pipeline-version-integer-persists-across-update"
GROUP = "state-machine"
SERVICES = ["codepipeline"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The pipeline version number returned by GetPipeline increments by exactly one
    integer per successful UpdatePipeline call, with no precision loss or drift, across
    several successive updates."""
    cp = ctx.client("codepipeline")
    bucket = _create_artifact_bucket(ctx)
    role_arn = _create_pipeline_role(ctx, bucket)
    source_action = _create_custom_action_type(ctx, "Source", ctx.unique_name("SimSrc").replace("-", ""), output_range=(1, 1))
    build_action = _create_custom_action_type(
        ctx,
        "Build",
        ctx.unique_name("SimBld").replace("-", ""),
        input_range=(1, 1),
        config_properties=[
            {"name": "Marker", "required": False, "key": True, "secret": False, "queryable": False}
        ],
    )

    name = ctx.unique_name("sim2real-cp-")
    base_stages = _worker_pipeline_stages(source_action["provider"], build_action["provider"])
    pipeline_def = {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "stages": base_stages,
    }
    created = _create_pipeline(ctx, pipeline_def, tags=[{"key": "sim2real", "value": CHECK}])
    assert created["version"] == 1, f"expected version 1 on CreatePipeline, got {created['version']!r}"
    assert isinstance(created["version"], int), f"expected an int version, got {type(created['version'])!r}"

    current = cp.get_pipeline(name=name)["pipeline"]
    assert current["version"] == 1, f"expected GetPipeline to echo version 1, got {current['version']!r}"

    expected_version = 1
    for i in range(3):
        # Trivial, semantically-inert change to the Build action's configuration so each
        # UpdatePipeline call is a genuine structural update.
        current["stages"][1]["actions"][0]["configuration"] = {"Marker": f"round-{i}"}
        updated = cp.update_pipeline(pipeline=current)["pipeline"]
        expected_version += 1
        assert updated["version"] == expected_version, (
            f"round {i}: expected UpdatePipeline to bump version to {expected_version}, got {updated['version']!r}"
        )
        assert isinstance(updated["version"], int), f"round {i}: expected an int version, got {type(updated['version'])!r}"
        current = updated

    final = cp.get_pipeline(name=name)["pipeline"]
    assert final["version"] == expected_version == 4, (
        f"expected GetPipeline to reflect the final version 4 (tracked as {expected_version}), got {final['version']!r}"
    )


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
    # us-east-1 is the one region where S3 CreateBucket forbids an explicit LocationConstraint;
    # every other region requires it. Region-pinned by the S3 API itself, not a choice made here.
    if ctx.region == "us-east-1":
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


def _create_custom_action_type(ctx, category: str, provider: str, *, input_range=(0, 0), output_range=(0, 0), config_properties=None) -> dict[str, str]:
    cp = ctx.client("codepipeline")
    kwargs: dict[str, Any] = dict(
        category=category,
        provider=provider,
        version="1",
        inputArtifactDetails={"minimumCount": input_range[0], "maximumCount": input_range[1]},
        outputArtifactDetails={"minimumCount": output_range[0], "maximumCount": output_range[1]},
    )
    if config_properties:
        kwargs["configurationProperties"] = config_properties
    kwargs["tags"] = [{"key": "sim2real", "value": CHECK}]
    cp.create_custom_action_type(**kwargs)
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


def _create_pipeline(ctx, pipeline_def: dict[str, Any], *, tags=None, timeout_s: float = 90.0, interval_s: float = 5.0) -> dict[str, Any]:
    """CreatePipeline can transiently report a freshly created role as unassumable
    (InvalidStructureException/ValidationException mentioning AssumeRole) while IAM propagates
    it; IAM exposes no read that confirms cross-service propagation, so this retries the real
    call itself, bounded by a deadline, rather than sleeping a fixed guess beforehand. Any other
    error is structural and re-raised immediately."""
    cp = ctx.client("codepipeline")
    kwargs: dict[str, Any] = {"pipeline": pipeline_def}
    if tags is not None:
        kwargs["tags"] = tags
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            resp = cp.create_pipeline(**kwargs)
            break
        except ClientError as err:
            error = err.response["Error"]
            transient = error["Code"] in ("InvalidStructureException", "ValidationException") and "AssumeRole" in error.get(
                "Message", ""
            )
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
    name = pipeline_def["name"]
    ctx.on_cleanup(lambda: _safe_delete_pipeline(cp, name))
    return resp["pipeline"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
