"""put-approval-result-token-invalidated-after-completion."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags

CHECK = "put-approval-result-token-invalidated-after-completion"
GROUP = "error-semantics"
SERVICES = ["codepipeline"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """After a manual approval succeeds with its token, reusing the token fails with
    ApprovalAlreadyCompletedException and its exact message, and the action stays Succeeded with an unchanged
    lastStatusChange.
    """
    cp = ctx.client("codepipeline")
    bucket = _create_artifact_bucket(ctx)
    role_arn = _create_pipeline_role(ctx, bucket)
    pipeline_name = _create_pipeline(
        ctx,
        role_arn,
        bucket,
        stages=[
            _source_stage(bucket),
            {
                "name": "Approval",
                "actions": [
                    {
                        "name": "Approve",
                        "actionTypeId": {
                            "category": "Approval",
                            "owner": "AWS",
                            "provider": "Manual",
                            "version": "1",
                        },
                    }
                ],
            },
        ],
    )

    cp.start_pipeline_execution(name=pipeline_name)

    state = _poll_until(
        lambda: cp.get_pipeline_state(name=pipeline_name),
        lambda st: next(s for s in st["stageStates"] if s["stageName"] == "Approval")["actionStates"][0]
        .get("latestExecution", {})
        .get("token")
        is not None,
        timeout_s=90.0,
        interval_s=3.0,
    )
    approval_stage = next(s for s in state["stageStates"] if s["stageName"] == "Approval")
    token = approval_stage["actionStates"][0]["latestExecution"]["token"]

    # Positive control: the first use of this token genuinely succeeds.
    cp.put_approval_result(
        pipelineName=pipeline_name,
        stageName="Approval",
        actionName="Approve",
        result={"summary": "first approval", "status": "Approved"},
        token=token,
    )
    approved_state = _poll_until(
        lambda: cp.get_pipeline_state(name=pipeline_name),
        lambda st: next(s for s in st["stageStates"] if s["stageName"] == "Approval")["actionStates"][0][
            "latestExecution"
        ]["status"]
        == "Succeeded",
        timeout_s=60.0,
        interval_s=3.0,
    )
    approved_action = next(s for s in approved_state["stageStates"] if s["stageName"] == "Approval")[
        "actionStates"
    ][0]
    assert approved_action["latestExecution"]["status"] == "Succeeded", (
        f"expected the positive control to reach Succeeded, got {approved_action['latestExecution']['status']!r}"
    )
    last_change_before = approved_action["latestExecution"]["lastStatusChange"]

    # Negative: reusing the same token fails, and does not re-run the approval.
    error = _error(
        lambda: cp.put_approval_result(
            pipelineName=pipeline_name,
            stageName="Approval",
            actionName="Approve",
            result={"summary": "second use of the same token", "status": "Approved"},
            token=token,
        )
    )
    assert error.get("Code") == "ApprovalAlreadyCompletedException", error
    expected_message = (
        "The approval request that you responded to is already complete or has expired. "
        "Review the latest revisions in the pipeline, and then try again."
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    unchanged_state = cp.get_pipeline_state(name=pipeline_name)
    unchanged_action = next(s for s in unchanged_state["stageStates"] if s["stageName"] == "Approval")[
        "actionStates"
    ][0]
    assert unchanged_action["latestExecution"]["status"] == "Succeeded", (
        f"expected the rejected reuse to leave status Succeeded, got {unchanged_action['latestExecution']['status']!r}"
    )
    assert unchanged_action["latestExecution"]["lastStatusChange"] == last_change_before, (
        "the rejected reuse of the token must not have re-processed the approval action"
    )


def _error(fn) -> dict:
    """Call fn and return the botocore Error dict; raise if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("README.txt", "sim2real behavioral check source artifact")
    return buf.getvalue()


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-art-").lower().replace("_", "-")
    kwargs = {}
    # us-east-1 is S3's CreateBucket default region: passing a LocationConstraint for it is
    # rejected (InvalidLocationConstraint), so the constraint is only supplied elsewhere.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket):
            objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
            objs += [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("DeleteMarkers", [])]
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    s3.put_object(Bucket=bucket, Key="source.zip", Body=_zip_bytes())
    return bucket


def _create_pipeline_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codepipeline.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "artifact-access"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:GetObjectVersion",
                    "s3:PutObject",
                    "s3:GetBucketVersioning",
                    "s3:GetBucketAcl",
                    "s3:GetBucketLocation",
                    "s3:ListBucket",
                ],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role["Arn"]


def _source_stage(bucket: str) -> dict:
    return {
        "name": "Source",
        "actions": [
            {
                "name": "Source",
                "actionTypeId": {"category": "Source", "owner": "AWS", "provider": "S3", "version": "1"},
                "configuration": {
                    "S3Bucket": bucket,
                    "S3ObjectKey": "source.zip",
                    "PollForSourceChanges": "false",
                },
                "outputArtifacts": [{"name": "SourceOutput"}],
            }
        ],
    }


def _create_pipeline(ctx, role_arn: str, bucket: str, stages: list, pipeline_type=None) -> str:
    cp = ctx.client("codepipeline")
    name = ctx.unique_name("sim2real-cp-pl-")
    pipeline = {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "stages": stages,
    }
    if pipeline_type:
        pipeline["pipelineType"] = pipeline_type

    # Bounded retry, not a fixed pre-sleep: the role just created by
    # _create_pipeline_role needs a few seconds to propagate through IAM before
    # CodePipeline can assume it, and this absorbs that delay without waiting
    # longer than necessary.
    deadline = time.monotonic() + 60.0
    while True:
        try:
            cp.create_pipeline(pipeline=pipeline, tags=[{"key": "sim2real", "value": CHECK}])
            break
        except Exception:
            if time.monotonic() > deadline:
                raise
            time.sleep(5)
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
