"""condition-not-overridable-rejected."""
from __future__ import annotations

import json
import time
import uuid
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "condition-not-overridable-rejected"
GROUP = "error-semantics"
SERVICES = ["codepipeline"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """OverrideStageCondition on a beforeEntry condition that resolved with a Skip
    result is rejected with ConditionNotOverridableException, as documented: a
    condition configured with a Skip result cannot be overridden."""
    cp = ctx.client("codepipeline")
    src_type = _create_custom_action_type(ctx, "Source", 0, 0, 1, 1)
    gate_type = _create_custom_action_type(ctx, "Build", 1, 1, 0, 1)

    var_check = {"category": "Rule", "owner": "AWS", "provider": "VariableCheck", "version": "1"}
    stages = [
        {
            "name": "Source",
            "actions": [
                {
                    "name": "SourceAction",
                    "actionTypeId": src_type,
                    "outputArtifacts": [{"name": "SourceOutput"}],
                    "namespace": "Vars",
                }
            ],
        },
        {
            "name": "GateSkip",
            "actions": [
                {
                    "name": "GateSkipAction",
                    "actionTypeId": gate_type,
                    "inputArtifacts": [{"name": "SourceOutput"}],
                    "outputArtifacts": [{"name": "SkipOutput"}],
                }
            ],
            "beforeEntry": {
                "conditions": [
                    {
                        "result": "SKIP",
                        "rules": [
                            {
                                "name": "SkipRule",
                                "ruleTypeId": var_check,
                                "configuration": {
                                    "Variable": "#{Vars.Flag}",
                                    "Value": "yes",
                                    "Operator": "EQ",
                                },
                                "inputArtifacts": [],
                            }
                        ],
                    }
                ]
            },
        },
    ]
    pipeline_name = _create_pipeline(ctx, stages, pipeline_type="V2")

    execution_id = cp.start_pipeline_execution(name=pipeline_name)["pipelineExecutionId"]
    _drive_job(ctx, src_type, output_variables={"Flag": "no"})  # "no" != "yes" -> the rule fails

    # --- negative: the Skip-result condition on GateSkip cannot be overridden ---
    stage_status = _poll_until(
        lambda: _stage_status(cp, pipeline_name, "GateSkip"),
        lambda status: status not in (None, "DidNotRun"),
        timeout_s=180,
        interval_s=5,
    )
    assert stage_status == "Skipped", stage_status

    code, message = _error(
        lambda: cp.override_stage_condition(
            pipelineName=pipeline_name,
            stageName="GateSkip",
            pipelineExecutionId=execution_id,
            conditionType="BEFORE_ENTRY",
        )
    )
    assert code == "ConditionNotOverridableException", code
    assert message == (
        "The condition type BEFORE_ENTRY in stage GateSkip cannot be overridden now. "
        "Either it contains no failed or in-progress rule, "
        f"the execution '{pipeline_name}' is already superseded, "
        "or the pipeline definition has changed since the rules(s) failed."
    ), f"unexpected message: {message!r}"

    # effect absent: GateSkip's status is unchanged, still Skipped
    post_status = _stage_status(cp, pipeline_name, "GateSkip")
    assert post_status == "Skipped", f"expected Skipped, got {post_status}"


def _stage_status(cp, pipeline_name: str, stage_name: str) -> str | None:
    states = cp.get_pipeline_state(name=pipeline_name)["stageStates"]
    for s in states:
        if s["stageName"] == stage_name:
            return s.get("latestExecution", {}).get("status")
    raise AssertionError(f"stage {stage_name} not found in {states}")



# ===== helpers =====


def _short_id() -> str:
    return uuid.uuid4().hex[:10]


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-cp-art-").lower()
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        # us-east-1 is S3's own default region and rejects an explicit LocationConstraint.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        try:
            versions = s3.list_object_versions(Bucket=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise
            return
        objs = [
            {"Key": v["Key"], "VersionId": v["VersionId"]}
            for v in versions.get("Versions", []) + versions.get("DeleteMarkers", [])
        ]
        if objs:
            failed = s3.delete_objects(Bucket=name, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _create_pipeline_role(ctx, bucket_name: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp-role-")
    trust = json.dumps(
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    policy_name = "artifact-access"
    policy = json.dumps(
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
                    "Resource": [
                        f"arn:aws:s3:::{bucket_name}",
                        f"arn:aws:s3:::{bucket_name}/*",
                    ],
                }
            ],
        }
    )
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=policy)

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_custom_action_type(ctx, category: str, min_in: int, max_in: int, min_out: int, max_out: int):
    cp = ctx.client("codepipeline")
    provider = f"S2R{category[:2]}{_short_id()}"[:35]
    version = "1"
    cp.create_custom_action_type(
        category=category,
        provider=provider,
        version=version,
        inputArtifactDetails={"minimumCount": min_in, "maximumCount": max_in},
        outputArtifactDetails={"minimumCount": min_out, "maximumCount": max_out},
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    ctx.on_cleanup(
        lambda: cp.delete_custom_action_type(category=category, provider=provider, version=version)
    )
    return {"category": category, "owner": "Custom", "provider": provider, "version": version}


def _create_pipeline(ctx, stages: list[dict], pipeline_type: str = "V1") -> str:
    cp = ctx.client("codepipeline")
    bucket = _create_artifact_bucket(ctx)
    role_arn = _create_pipeline_role(ctx, bucket)
    name = ctx.unique_name("sim2real-cp-")
    pipeline_def: dict[str, Any] = {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "stages": stages,
    }
    if pipeline_type == "V2":
        pipeline_def["pipelineType"] = "V2"
    tags = [{"key": "sim2real", "value": CHECK}]

    # A freshly created role is not immediately assumable by CodePipeline (IAM
    # propagation is eventually consistent); retry only on the specific codes
    # that mean "the role isn't ready yet", bounded by a 60s deadline.
    left = ctx.time_left()
    deadline = time.monotonic() + (60.0 if left is None else min(60.0, left))
    while True:
        try:
            cp.create_pipeline(pipeline=pipeline_def, tags=tags)
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code not in ("InvalidStructureException", "ValidationException") or time.monotonic() >= deadline:
                raise
            time.sleep(2)

    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))
    return name


def _dummy_zip_bytes() -> bytes:
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("artifact.txt", "sim2real-behavioral-test-artifact")
    return buf.getvalue()


def _drive_job(ctx, action_type_id: dict, outcome: str = "success", output_variables: dict | None = None,
                failure_message: str = "boom"):
    cp = ctx.client("codepipeline")
    s3 = ctx.client("s3")
    jobs = _poll_until(
        lambda: cp.poll_for_jobs(actionTypeId=action_type_id, maxBatchSize=1).get("jobs", []),
        lambda j: len(j) > 0,
        timeout_s=60,
        interval_s=3,
    )
    job = jobs[0]
    job_id = job["id"]
    nonce = job["nonce"]
    cp.acknowledge_job(jobId=job_id, nonce=nonce)
    if outcome == "success":
        details = cp.get_job_details(jobId=job_id)["jobDetails"]
        for artifact in details["data"].get("outputArtifacts", []):
            loc = (artifact.get("location") or {}).get("s3Location")
            if loc:
                s3.put_object(Bucket=loc["bucketName"], Key=loc["objectKey"], Body=_dummy_zip_bytes())
        kwargs: dict[str, Any] = {
            "jobId": job_id,
            "currentRevision": {"revision": "1", "changeIdentifier": _short_id()},
        }
        if output_variables:
            kwargs["outputVariables"] = output_variables
        cp.put_job_success_result(**kwargs)
    else:
        cp.put_job_failure_result(
            jobId=job_id, failureDetails={"type": "JobFailed", "message": failure_message}
        )
    return job


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
