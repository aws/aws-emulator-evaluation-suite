"""action-configuration-empty-string-vs-absent-preserved."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "action-configuration-empty-string-vs-absent-preserved"
GROUP = "server-side"
SERVICES = ["codepipeline"]

# ActionConfigurationValue forbids empty strings (length min=1), so an action-configuration
# field literally cannot be "set to empty string" -- CreatePipeline would reject it. The field
# that DOES allow an explicit empty string is PipelineVariableDeclaration.description
# (length min=0, max=200). This check exercises that field: one pipeline variable with
# description explicitly set to "" versus a second variable with no description key at all.


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A pipeline variable's description="" is distinguishable from an omitted description after an update round trip."""
    cp = ctx.client("codepipeline")
    bucket = _create_artifact_bucket(ctx)
    role_arn = _create_pipeline_role(ctx, bucket)

    source_provider = ctx.unique_name("sim2real-cp-src-")
    build_provider = ctx.unique_name("sim2real-cp-bld-")
    _create_custom_action_type(ctx, "Source", source_provider, "1", 0, 0, 1, 1)
    _create_custom_action_type(ctx, "Build", build_provider, "1", 1, 1, 0, 1)

    pipeline_name = ctx.unique_name("sim2real-cp-pipe-")
    variables = [
        {"name": "VarWithEmptyDesc", "defaultValue": "v1", "description": ""},
        {"name": "VarNoDesc", "defaultValue": "v2"},
    ]

    def _pipeline():
        return {
            "name": pipeline_name,
            "roleArn": role_arn,
            "pipelineType": "V2",
            "artifactStore": {"type": "S3", "location": bucket},
            "variables": variables,
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
                        "configuration": {},
                    }],
                },
            ],
        }

    _create_with_role_propagation(
        cp, _pipeline(), tags=[{"key": "sim2real", "value": pipeline_name}]
    )
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=pipeline_name))

    _assert_variables_distinguishable(cp, pipeline_name)

    # Round trip through UpdatePipeline (resubmitting the identical structure) and re-check.
    cp.update_pipeline(pipeline=_pipeline())
    _assert_variables_distinguishable(cp, pipeline_name)


def _assert_variables_distinguishable(cp, pipeline_name):
    fetched = cp.get_pipeline(name=pipeline_name)["pipeline"]
    by_name = {v["name"]: v for v in fetched["variables"]}
    with_desc = by_name["VarWithEmptyDesc"]
    without_desc = by_name["VarNoDesc"]

    assert "description" in with_desc, "explicit empty description was dropped, indistinguishable from absent"
    assert with_desc["description"] == "", with_desc["description"]
    assert "description" not in without_desc, (
        f"omitted description resurfaced as a key: {without_desc!r}"
    )


def _create_with_role_propagation(cp, declaration, *, tags=None, timeout_s: float = 90.0, interval_s: float = 5.0):
    """CreatePipeline can transiently report a freshly created role as unassumable
    (InvalidStructureException mentioning AssumeRole) while IAM propagates it; IAM exposes
    no read that confirms cross-service propagation, so this retries the real call itself
    rather than sleeping a fixed guess. Any other error is structural and re-raised
    immediately."""
    kwargs = {"pipeline": declaration}
    if tags is not None:
        kwargs["tags"] = tags
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return cp.create_pipeline(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            transient = err.get("Code") == "InvalidStructureException" and "AssumeRole" in err.get("Message", "")
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-art-").lower().replace("_", "-")[:63]
    kwargs = {"Bucket": bucket}
    # us-east-1 is the one region where S3 CreateBucket forbids an explicit LocationConstraint;
    # every other region requires it. Region-pinned by the S3 API itself, not a choice made here.
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
    }
    if config_props:
        kwargs["configurationProperties"] = config_props
    kwargs["tags"] = [{"key": "sim2real", "value": CHECK}]
    cp.create_custom_action_type(**kwargs)
    ctx.on_cleanup(lambda: cp.delete_custom_action_type(category=category, provider=provider, version=version))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
