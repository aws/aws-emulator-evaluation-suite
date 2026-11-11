"""create-pipeline-duplicate-name-in-use-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-pipeline-duplicate-name-in-use-rejected"
GROUP = 'error-semantics'
SERVICES = ['codepipeline']

_SCENARIO = 'codepipeline-create-pipeline-duplicate-name-in-use'


def _poll(fn, pred, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


def _account_id(ctx) -> str:
    """The target's account id, the same source on every target."""
    return ctx.account


def _purge_bucket(s3, bucket) -> None:
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
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-cpart-")
    kw = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kw["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kw)
    ctx.on_cleanup(lambda: _purge_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket,
                          Tagging={"TagSet": [{"Key": "sim2real", "Value": _SCENARIO}]})
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    return bucket


def _assumable_role(ctx, bucket) -> str:
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
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
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


def _declaration(name, role_arn, bucket, *, gate_action_name="ApproveAction"):
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
                "name": "Gate",
                "actions": [{
                    "name": gate_action_name,
                    "actionTypeId": {"category": "Approval", "owner": "AWS",
                                     "provider": "Manual", "version": "1"},
                    "runOrder": 1,
                }],
            },
        ],
    }


def _create_with_role_propagation(cp, declaration, *, timeout_s, pipeline_tags=None):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            kw = {"pipeline": declaration}
            if pipeline_tags is not None:
                kw["tags"] = pipeline_tags
            return cp.create_pipeline(**kw)
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreatePipeline with an existing name fails with PipelineNameInUseException and its exact message,
    GetPipeline still returns the first declaration at version 1, and exactly one pipeline of that name is
    listed.
    """
    cp = ctx.client("codepipeline")
    bucket = _artifact_store(ctx)
    role_arn = _assumable_role(ctx, bucket)
    timeout_s = 180

    pipeline_tags = [{"key": "sim2real", "value": _SCENARIO}]
    name = ctx.unique_name("sim2real-behav-cpdup-")
    first = _create_with_role_propagation(
        cp, _declaration(name, role_arn, bucket, gate_action_name="FirstApproval"),
        timeout_s=timeout_s, pipeline_tags=pipeline_tags,
    )
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))
    assert first["pipeline"]["version"] == 1, (
        f"a freshly created pipeline must be version 1, got {first['pipeline']['version']!r}"
    )

    # Break exactly one thing: reuse the name. Everything else differs only so that an
    # upsert-shaped emulator is detectable.
    try:
        result = cp.create_pipeline(
            pipeline=_declaration(name, role_arn, bucket, gate_action_name="SecondApproval")
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    else:
        raise AssertionError(f"CreatePipeline on an existing name succeeded and returned {result!r}")
    assert code == "PipelineNameInUseException", (
        f"CreatePipeline on an existing name returned {code!r}, expected "
        f"PipelineNameInUseException (an upsert here silently destroys the incumbent)"
    )
    assert message == f"A pipeline with the name '{name}' already exists in account '{ctx.account}'", (
        f"CreatePipeline on an existing name returned message {message!r}"
    )

    # Effect absent: the incumbent declaration is untouched and still at version 1.
    after = cp.get_pipeline(name=name)["pipeline"]
    assert after["version"] == 1, (
        f"pipeline version changed after a rejected duplicate create: {after['version']!r}"
    )
    gate_actions = [a["name"] for a in after["stages"][1]["actions"]]
    assert gate_actions == ["FirstApproval"], (
        f"the rejected duplicate create overwrote the incumbent declaration: Gate actions are "
        f"{gate_actions}, expected ['FirstApproval']"
    )
    assert _names(cp).count(name) == 1, (
        f"ListPipelines reports {_names(cp).count(name)} pipelines named {name}, expected 1"
    )

    # Control: a different name still creates, so the emulator is not just refusing creates.
    other = ctx.unique_name("sim2real-behav-cpctl-")
    _create_with_role_propagation(cp, _declaration(other, role_arn, bucket),
                                   timeout_s=timeout_s, pipeline_tags=pipeline_tags)
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=other))
    listed = _poll(lambda: _names(cp), lambda ns: other in ns, timeout_s=timeout_s, interval_s=3)
    assert other in listed, f"control pipeline {other} not visible in ListPipelines"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
