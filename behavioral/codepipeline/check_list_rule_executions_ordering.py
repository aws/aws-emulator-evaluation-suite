"""list-rule-executions-ordering."""
from __future__ import annotations

import json
import time
import uuid
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-rule-executions-ordering"
GROUP = "ordering"
SERVICES = ["codepipeline"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListRuleExecutions returns beforeEntry rule records most-recently-evaluated first: a later
    stage's rule runs only after the earlier stage completes, so it is returned first."""
    cp = ctx.client("codepipeline")
    src_type = _create_custom_action_type(ctx, "Source", 0, 0, 1, 1)
    gate1_type = _create_custom_action_type(ctx, "Build", 1, 1, 0, 1)
    gate2_type = _create_custom_action_type(ctx, "Build", 1, 1, 0, 1)

    var_check = {"category": "Rule", "owner": "AWS", "provider": "VariableCheck", "version": "1"}

    def _entry_condition(rule_name: str) -> dict:
        return {
            "conditions": [
                {
                    "result": "FAIL",
                    "rules": [
                        {
                            "name": rule_name,
                            "ruleTypeId": var_check,
                            "configuration": {
                                "Variable": "#{Vars.Flag}",
                                "Value": "ok",
                                "Operator": "EQ",
                            },
                            "inputArtifacts": [],
                        }
                    ],
                }
            ]
        }

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
            "name": "Gate1",
            "actions": [
                {
                    "name": "Gate1Action",
                    "actionTypeId": gate1_type,
                    "inputArtifacts": [{"name": "SourceOutput"}],
                    "outputArtifacts": [{"name": "Gate1Output"}],
                }
            ],
            "beforeEntry": _entry_condition("EntryRule1"),
        },
        {
            "name": "Gate2",
            "actions": [
                {
                    "name": "Gate2Action",
                    "actionTypeId": gate2_type,
                    "inputArtifacts": [{"name": "Gate1Output"}],
                    "outputArtifacts": [{"name": "Gate2Output"}],
                }
            ],
            "beforeEntry": _entry_condition("EntryRule2"),
        },
    ]
    pipeline_name = _create_pipeline(ctx, stages, pipeline_type="V2")

    resp = cp.start_pipeline_execution(name=pipeline_name)
    resp["pipelineExecutionId"]

    # Flag == "ok" everywhere -> both entry conditions PASS (never engage
    # their FAIL result), so both gate stages proceed to run their action.
    _drive_job(ctx, src_type, output_variables={"Flag": "ok"})
    _drive_job(ctx, gate1_type)
    _drive_job(ctx, gate2_type)

    rule_details = _poll_until(
        lambda: cp.list_rule_executions(pipelineName=pipeline_name)["ruleExecutionDetails"],
        lambda d: len(d) >= 2,
        timeout_s=200,
        interval_s=10,
    )

    assert len(rule_details) == 2, rule_details
    names = [d["ruleName"] for d in rule_details]
    assert set(names) == {"EntryRule1", "EntryRule2"}, names
    # EntryRule2 (Gate2's beforeEntry) can only run after Gate1 has fully
    # completed, so it is evaluated strictly later than EntryRule1 and must
    # be the more-recently-evaluated (first-returned) record.
    assert names[0] == "EntryRule2", names
    assert names[1] == "EntryRule1", names
    start_times = [d["startTime"] for d in rule_details]
    assert start_times[0] >= start_times[1], start_times
    assert all(d["status"] == "Succeeded" for d in rule_details), rule_details




def _short_id() -> str:
    return uuid.uuid4().hex[:10]


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
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)
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

    _create_with_role_propagation(cp, pipeline_def, timeout_s=30)

    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))
    return name


def _create_with_role_propagation(cp, declaration: dict, *, timeout_s: float) -> None:
    """IAM role propagation is real: CreatePipeline can transiently report the role as
    unassumable. Retry only that specific transient, never a structural rejection."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            cp.create_pipeline(pipeline=declaration)
            return
        except ClientError as exc:
            err = exc.response.get("Error", {})
            transient = (
                err.get("Code") == "InvalidStructureException"
                and "AssumeRole" in err.get("Message", "")
            )
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(5)


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
