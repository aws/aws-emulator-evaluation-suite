"""missing-s3-source-bucket-fails-the-source-action-with-its-error-details."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "missing-s3-source-bucket-fails-the-source-action-with-its-error-details"
GROUP = "error-semantics"
SERVICES = ["codepipeline"]

_TERMINAL = ("Succeeded", "Failed", "Stopped", "Cancelled", "Superseded")
_SCENARIO = "codepipeline-missing-source-bucket"


#: The S3 source action's errorDetails (code, message) for a source bucket that does not exist;
#: ``{}`` is the bucket name.
_MISSING_BUCKET = ("ConfigurationError", "[No bucket with the name {} was found]")


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, capped by the runner's remaining time less a cleanup margin."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 30.0))


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _poll(fn, pred, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


def _purge_bucket(s3, bucket) -> None:
    """Executions write versions into the store; a versioned bucket needs version-aware deletion."""
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


def _artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-cp-")
    kw = {"Bucket": bucket}
    # us-east-1 is S3's implicit default location; CreateBucket rejects an explicit
    # LocationConstraint naming it, so the literal here is the region exception, not a pin.
    if ctx.region != "us-east-1":
        kw["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    ctx.on_cleanup(_teardown(lambda: _purge_bucket(s3, bucket), "NoSuchBucket"))
    s3.create_bucket(**kw)
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": _SCENARIO}]}
    )
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    return bucket


def _pipeline_role(ctx, buckets) -> str:
    """A pipeline role granted S3 access on every bucket named.

    The missing source bucket is included, so the failure is its absence, never a permission denial.
    """
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-cp-")
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(
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
        ),
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
    )["Role"]["Arn"]
    partition = role_arn.split(":")[1]
    ctx.on_cleanup(
        _teardown(
            lambda: iam.delete_role_policy(RoleName=name, PolicyName="artifacts"), "NoSuchEntity"
        )
    )
    resources = [
        r for b in buckets for r in (f"arn:{partition}:s3:::{b}", f"arn:{partition}:s3:::{b}/*")
    ]
    iam.put_role_policy(
        RoleName=name,
        PolicyName="artifacts",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:GetObject",
                            "s3:GetObjectVersion",
                            "s3:PutObject",
                            "s3:GetBucketVersioning",
                            "s3:ListBucket",
                        ],
                        "Resource": resources,
                    }
                ],
            }
        ),
    )
    return role_arn


def _create_with_role_propagation(cp, declaration, *, timeout_s, pipeline_tags=None):
    """CreatePipeline, retried while the fresh role propagates.

    CreatePipeline answers InvalidStructureException naming AssumeRole until then; the bounded
    retry is the wait.
    """
    deadline = time.monotonic() + timeout_s
    kw = {"pipeline": declaration}
    if pipeline_tags:
        kw["tags"] = pipeline_tags
    while True:
        try:
            return cp.create_pipeline(**kw)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            transient = err.get("Code") == "InvalidStructureException" and "AssumeRole" in err.get(
                "Message", ""
            )
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(5)


def _execution_ids(cp, name):
    ids = []
    for page in cp.get_paginator("list_pipeline_executions").paginate(pipelineName=name):
        ids.extend(s["pipelineExecutionId"] for s in page.get("pipelineExecutionSummaries", []))
    return ids


def _execution_status(cp, name, execution_id):
    try:
        return cp.get_pipeline_execution(pipelineName=name, pipelineExecutionId=execution_id)[
            "pipelineExecution"
        ]["status"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "PipelineExecutionNotFoundException":
            return None
        raise


def _action_state(cp, name, stage_name, action_name):
    for stage in cp.get_pipeline_state(name=name).get("stageStates", []):
        if stage.get("stageName") == stage_name:
            for action in stage.get("actionStates", []):
                if action.get("actionName") == action_name:
                    return action
    return {}


def _source_action_executions(cp, name, execution_id):
    out, token = [], None
    while True:
        kw = {"pipelineName": name, "filter": {"pipelineExecutionId": execution_id}}
        if token:
            kw["nextToken"] = token
        page = cp.list_action_executions(**kw)
        out.extend(
            d for d in page.get("actionExecutionDetails", []) if d.get("actionName") == "Source"
        )
        token = page.get("nextToken")
        if not token:
            return out


def _abandon(cp, name, execution_id):
    try:
        cp.stop_pipeline_execution(
            pipelineName=name,
            pipelineExecutionId=execution_id,
            abandon=True,
            reason="sim2real behavioral check teardown",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "PipelineNotFoundException",
            "PipelineExecutionNotStoppableException",
        ):
            raise


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """An S3 source action whose bucket does not exist fails the execution.

    GetPipelineState reports errorDetails with the code and a message naming the bucket;
    ListActionExecutions reports the code alone and carries that message as the execution summary.
    """
    cp = ctx.client("codepipeline")
    cap_s = 300.0

    artifact_bucket = _artifact_bucket(ctx)
    missing_bucket = ctx.unique_name("sim2real-behav-cpabsent-")
    role_arn = _pipeline_role(ctx, [artifact_bucket, missing_bucket])
    expected = {"code": _MISSING_BUCKET[0], "message": _MISSING_BUCKET[1].format(missing_bucket)}

    name = ctx.unique_name("sim2real-behav-cpnobkt-")
    ctx.on_cleanup(_teardown(lambda: cp.delete_pipeline(name=name), "PipelineNotFoundException"))
    _create_with_role_propagation(
        cp,
        {
            "name": name,
            "roleArn": role_arn,
            "artifactStore": {"type": "S3", "location": artifact_bucket},
            "pipelineType": "V2",
            "executionMode": "QUEUED",
            "stages": [
                {
                    "name": "Source",
                    "actions": [
                        {
                            "name": "Source",
                            "actionTypeId": {
                                "category": "Source",
                                "owner": "AWS",
                                "provider": "S3",
                                "version": "1",
                            },
                            "runOrder": 1,
                            "configuration": {
                                "S3Bucket": missing_bucket,
                                "S3ObjectKey": "source.zip",
                                "PollForSourceChanges": "false",
                            },
                            "outputArtifacts": [{"name": "SourceOutput"}],
                        }
                    ],
                },
                {
                    "name": "Deploy",
                    "actions": [
                        {
                            "name": "Deploy",
                            "actionTypeId": {
                                "category": "Deploy",
                                "owner": "AWS",
                                "provider": "S3",
                                "version": "1",
                            },
                            "runOrder": 1,
                            "configuration": {
                                "BucketName": artifact_bucket,
                                "Extract": "false",
                                "ObjectKey": "deployed/out.zip",
                            },
                            "inputArtifacts": [{"name": "SourceOutput"}],
                        }
                    ],
                },
            ],
        },
        timeout_s=_budget_s(ctx, 180.0),
        pipeline_tags=[{"key": "sim2real", "value": _SCENARIO}],
    )

    # CreatePipeline starts the execution this check grades.
    ids = _poll(
        lambda: _execution_ids(cp, name),
        lambda i: len(i) >= 1,
        timeout_s=_budget_s(ctx, cap_s),
        interval_s=3,
    )
    assert ids, f"CreatePipeline started no execution of {name!r}"
    execution_id = ids[0]
    ctx.on_cleanup(lambda: _abandon(cp, name, execution_id))
    status = _poll(
        lambda: _execution_status(cp, name, execution_id),
        lambda s: s in _TERMINAL,
        timeout_s=_budget_s(ctx, cap_s),
        interval_s=3,
    )
    assert status == "Failed", (
        f"a missing source bucket must fail execution {execution_id}, got {status!r}"
    )

    latest = _action_state(cp, name, "Source", "Source").get("latestExecution", {})
    assert latest.get("status") == "Failed", f"Source latestExecution was {latest!r}"
    assert latest.get("errorDetails") == expected, (
        f"GetPipelineState errorDetails must be {expected!r}, got {latest.get('errorDetails')!r}"
    )

    details = _source_action_executions(cp, name, execution_id)
    assert len(details) == 1, f"expected one Source action execution, got {details!r}"
    detail = details[0]
    assert detail.get("status") == "Failed", f"the Source action execution was {detail!r}"
    result = detail.get("output", {}).get("executionResult", {})
    want = {
        "errorDetails": {"code": expected["code"]},
        "externalExecutionSummary": expected["message"],
    }
    assert result == want, f"ListActionExecutions executionResult must be {want!r}, got {result!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
