"""create-pipeline-v1-rejects-v2-only-fields."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-pipeline-v1-rejects-v2-only-fields"
GROUP = 'error-semantics'
SERVICES = ['codepipeline']

# CodePipeline refuses both V2-only fields as a declaration-structure fault, each with its own
# message naming the field, so the check tests field compatibility rather than a blanket V1 rejection.
_ERR_STRUCTURE = "InvalidStructureException"
_MSG_VARIABLES = "Pipeline variable can only be used with V2 pipelines"
_MSG_EXECUTION_MODE = "QUEUED or PARALLEL mode can only be used with V2 pipelines"


_SCENARIO = 'codepipeline-create-pipeline-v1-rejects-v2-only-fields'


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


def _declaration(name, role_arn, bucket, *, pipeline_type, extra=None):
    d = {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "pipelineType": pipeline_type,
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
                    "name": "ApproveAction",
                    "actionTypeId": {"category": "Approval", "owner": "AWS",
                                     "provider": "Manual", "version": "1"},
                    "runOrder": 1,
                }],
            },
        ],
    }
    d.update(extra or {})
    return d


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


def _reject(cp, declaration):
    """Return (code, message) for a CreatePipeline that must be refused; raise if it is accepted."""
    try:
        result = cp.create_pipeline(pipeline=declaration)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected CreatePipeline to be refused, but it succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A V1 pipeline declaring variables or executionMode PARALLEL fails with InvalidStructureException and a
    message naming that field, while the same declaration as V2 is created and round-trips both fields.
    """
    cp = ctx.client("codepipeline")
    bucket = _artifact_store(ctx)
    role_arn = _assumable_role(ctx, bucket)
    timeout_s = 180

    v2_extra = {
        "executionMode": "PARALLEL",
        "variables": [{"name": "Flavor", "defaultValue": "vanilla",
                       "description": "V2-only pipeline variable"}],
    }

    # Control: V2 accepts both fields and echoes them back.
    control = ctx.unique_name("sim2real-behav-cpctl-")
    created = _create_with_role_propagation(
        cp, _declaration(control, role_arn, bucket, pipeline_type="V2", extra=v2_extra),
        timeout_s=timeout_s,
        pipeline_tags=[{"key": "sim2real", "value": _SCENARIO}],
    )
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=control))
    got = created["pipeline"]
    assert got.get("pipelineType") == "V2", f"pipelineType not echoed: {got.get('pipelineType')!r}"
    assert got.get("executionMode") == "PARALLEL", (
        f"executionMode not echoed on a V2 pipeline: {got.get('executionMode')!r}"
    )
    assert [v["name"] for v in got.get("variables", [])] == ["Flavor"], (
        f"variables not echoed on a V2 pipeline: {got.get('variables')!r}"
    )

    # Mutation 1: variables on V1.
    bad_vars = ctx.unique_name("sim2real-behav-cpv1var-")
    code, msg = _reject(cp, _declaration(
        bad_vars, role_arn, bucket, pipeline_type="V1",
        extra={"variables": v2_extra["variables"]},
    ))
    assert code == _ERR_STRUCTURE, (
        f"CreatePipeline accepted (or misclassified) `variables` on a V1 pipeline: "
        f"error code was {code!r}, expected {_ERR_STRUCTURE}"
    )
    assert msg == _MSG_VARIABLES, (
        f"the refusal must name `variables` as the V2-only field ({_MSG_VARIABLES!r}); a blanket "
        f"V1 rejection is not the same contract: {msg!r}"
    )

    # Mutation 2: executionMode PARALLEL on V1.
    bad_mode = ctx.unique_name("sim2real-behav-cpv1mode-")
    code, msg = _reject(cp, _declaration(
        bad_mode, role_arn, bucket, pipeline_type="V1",
        extra={"executionMode": "PARALLEL"},
    ))
    assert code == _ERR_STRUCTURE, (
        f"CreatePipeline accepted (or misclassified) `executionMode: PARALLEL` on a V1 "
        f"pipeline: error code was {code!r}, expected {_ERR_STRUCTURE}"
    )
    assert msg == _MSG_EXECUTION_MODE, (
        f"the refusal must name the offending execution mode ({_MSG_EXECUTION_MODE!r}), and it "
        f"must differ from the `variables` refusal -- two fields, two messages: {msg!r}"
    )

    # Effect absent for both, control intact.
    listed = _poll(
        lambda: _names(cp),
        lambda ns: bad_vars not in ns and bad_mode not in ns,
        timeout_s=timeout_s, interval_s=3,
    )
    assert bad_vars not in listed, f"rejected V1+variables pipeline {bad_vars} exists"
    assert bad_mode not in listed, f"rejected V1+executionMode pipeline {bad_mode} exists"
    assert control in listed, f"control pipeline {control} missing from ListPipelines"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
