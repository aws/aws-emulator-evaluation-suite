"""create-pipeline-dangling-input-artifact-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-pipeline-dangling-input-artifact-rejected"
GROUP = 'error-semantics'
SERVICES = ['codepipeline']


# ===== helpers =====
# No shared module is imported.

def _poll(fn, pred, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _account_id(ctx) -> str:
    """The target's account id, the same source on every target."""
    return ctx.account


def _purge_bucket(s3, bucket) -> None:
    """DeletePipeline does NOT delete the artifact store, and the artifact store must be
    versioned, so DeleteBucket fails unless every version AND delete marker is removed."""
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        objs = [
            {"Key": v["Key"], "VersionId": v["VersionId"]}
            for v in list(page.get("Versions", [])) + list(page.get("DeleteMarkers", []))
        ]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _artifact_store(ctx) -> str:
    """A versioned S3 artifact-store bucket, with version-aware teardown registered first
    (so LIFO cleanup purges it last, after the pipeline that references it is gone)."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-cpart-")
    kw = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kw["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kw)
    ctx.on_cleanup(lambda: _purge_bucket(s3, bucket))
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    return bucket


def _assumable_role(ctx, bucket) -> str:
    """A role CodePipeline can genuinely assume. Without one, CreatePipeline fails the AssumeRole
    check FIRST and masks every structural defect."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-cprole-")
    iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "codepipeline.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name,
        PolicyName="artifacts",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject",
                           "s3:GetBucketVersioning", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="artifacts"))
    return f"arn:aws:iam::{_account_id(ctx)}:role/{name}"


def _declaration(name, role_arn, bucket, *, build_input="SourceOutput"):
    """A structurally VALID two-stage pipeline. `build_input` is the single knob this check
    mutates: the Build action's inputArtifacts name."""
    return {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "pipelineType": "V2",
        "stages": [
            {
                "name": "Source",
                "actions": [{
                    "name": "SourceAction",
                    "actionTypeId": {"category": "Source", "owner": "AWS",
                                     "provider": "S3", "version": "1"},
                    "runOrder": 1,
                    "configuration": {"S3Bucket": bucket, "S3ObjectKey": "source.zip",
                                      "PollForSourceChanges": "false"},
                    "outputArtifacts": [{"name": "SourceOutput"}],
                }],
            },
            {
                "name": "Deploy",
                "actions": [{
                    "name": "DeployAction",
                    "actionTypeId": {"category": "Deploy", "owner": "AWS",
                                     "provider": "S3", "version": "1"},
                    "runOrder": 1,
                    "configuration": {"BucketName": bucket, "Extract": "false",
                                      "ObjectKey": "deployed/out.zip"},
                    "inputArtifacts": [{"name": build_input}],
                }],
            },
        ],
    }


def _create_with_role_propagation(cp, declaration, *, timeout_s):
    """IAM role propagation is real: CreatePipeline can transiently report the role as
    unassumable. Retry only that specific transient, never a structural rejection."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return cp.create_pipeline(pipeline=declaration)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            transient = (err.get("Code") == "InvalidStructureException"
                         and "AssumeRole" in err.get("Message", ""))
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(5)


def _names(cp):
    out = []
    for page in cp.get_paginator("list_pipelines").paginate():
        out.extend(p["name"] for p in page.get("pipelines", []))
    return out


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An action whose inputArtifacts names an artifact no earlier stage produces is refused with
    InvalidActionDeclarationException and no pipeline is created, while the identical
    declaration with the correct artifact name is accepted."""
    cp = ctx.client("codepipeline")
    bucket = _artifact_store(ctx)
    role_arn = _assumable_role(ctx, bucket)
    timeout_s = 180

    # Control first: the unmutated declaration must create. This also proves the role is
    # assumable, so a later structural rejection cannot be an AssumeRole artifact.
    control = ctx.unique_name("sim2real-behav-cpctl-")
    created = _create_with_role_propagation(
        cp, _declaration(control, role_arn, bucket), timeout_s=timeout_s
    )
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=control))
    assert created["pipeline"]["stages"][1]["actions"][0]["inputArtifacts"] == [
        {"name": "SourceOutput"}
    ], f"control pipeline did not round-trip its inputArtifacts: {created['pipeline']}"

    # Break exactly one thing: the Deploy action consumes an artifact nobody produces.
    bad = ctx.unique_name("sim2real-behav-cpbad-")
    code, message = _error(
        lambda: cp.create_pipeline(
            pipeline=_declaration(bad, role_arn, bucket, build_input="NoSuchArtifact")
        )
    )
    assert code == "InvalidActionDeclarationException", (
        f"CreatePipeline accepted (or misclassified) a dangling inputArtifacts reference: "
        f"error code was {code!r}, expected InvalidActionDeclarationException"
    )
    assert message == (
        "Input Artifact Bundle NoSuchArtifact in action DeployAction is not declared as "
        "Output Artifact Bundle in any of the preceding actions"
    ), f"CreatePipeline rejected the dangling reference with message {message!r}"

    # Effect absent: the rejected pipeline must not exist.
    listed = _poll(lambda: _names(cp), lambda ns: bad not in ns, timeout_s=timeout_s, interval_s=3)
    assert bad not in listed, f"rejected pipeline {bad} is present in ListPipelines"
    get_code, get_message = _error(lambda: cp.get_pipeline(name=bad))
    assert get_code == "PipelineNotFoundException", (
        f"GetPipeline on the rejected pipeline returned {get_code!r}, "
        f"expected PipelineNotFoundException"
    )
    assert get_message == f"Account '{ctx.account}' does not have a pipeline with name '{bad}'", (
        f"GetPipeline on the rejected pipeline returned message {get_message!r}"
    )

    # Control still readable: the rejection did not disturb the valid pipeline.
    assert control in _names(cp), f"control pipeline {control} vanished after the rejection"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
