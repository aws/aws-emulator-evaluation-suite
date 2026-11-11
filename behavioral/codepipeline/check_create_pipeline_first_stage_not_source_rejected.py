"""create-pipeline-first-stage-not-source-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-pipeline-first-stage-not-source-rejected"
GROUP = 'error-semantics'
SERVICES = ['codepipeline']


# ===== helpers =====

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
    """A versioned artifact store needs version-aware deletion or DeleteBucket fails."""
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
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    return bucket


def _assumable_role(ctx, bucket) -> str:
    """A role CodePipeline can genuinely assume, so the AssumeRole check does not mask the
    structural rejection under test."""
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


def _source_stage(bucket):
    return {
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
    }


def _approval_stage():
    """A manual-approval stage: zero cost, no downstream provisioning, and it consumes and
    produces no artifacts, so reordering it cannot introduce a second defect."""
    return {
        "name": "Gate",
        "actions": [{
            "name": "ApproveAction",
            "actionTypeId": {"category": "Approval", "owner": "AWS",
                             "provider": "Manual", "version": "1"},
            "runOrder": 1,
        }],
    }


def _declaration(name, role_arn, bucket, *, source_first=True):
    stages = [_source_stage(bucket), _approval_stage()]
    if not source_first:
        stages.reverse()
    return {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "pipelineType": "V2",
        "stages": stages,
    }


def _create_with_role_propagation(cp, declaration, *, timeout_s):
    """IAM propagation is real; retry only the transient AssumeRole failure."""
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
    """A pipeline whose first stage is not a source stage is refused with
    InvalidStructureException, while the same two stages in source-first order are accepted."""
    cp = ctx.client("codepipeline")
    bucket = _artifact_store(ctx)
    role_arn = _assumable_role(ctx, bucket)
    timeout_s = 180

    control = ctx.unique_name("sim2real-behav-cpctl-")
    created = _create_with_role_propagation(
        cp, _declaration(control, role_arn, bucket, source_first=True), timeout_s=timeout_s
    )
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=control))
    stage_names = [s["name"] for s in created["pipeline"]["stages"]]
    assert stage_names == ["Source", "Gate"], f"control stage order not preserved: {stage_names}"

    bad = ctx.unique_name("sim2real-behav-cpbad-")
    try:
        cp.create_pipeline(
            pipeline=_declaration(bad, role_arn, bucket, source_first=False)
        )
        code = None
        message = None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    assert code == "InvalidStructureException", (
        f"CreatePipeline accepted (or misclassified) a pipeline whose first stage is an "
        f"Approval stage and whose source action is in stage 2: error code was {code!r}, "
        f"expected InvalidStructureException"
    )
    assert message == "Pipeline should start with a stage that only contains source actions", (
        f"expected the exact InvalidStructureException message AWS returns, got {message!r}"
    )

    listed = _poll(lambda: _names(cp), lambda ns: bad not in ns, timeout_s=timeout_s, interval_s=3)
    assert bad not in listed, f"rejected pipeline {bad} is present in ListPipelines"
    assert control in listed, f"control pipeline {control} missing from ListPipelines"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
