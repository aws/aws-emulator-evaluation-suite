"""list-rule-executions-matches-condition-evaluation-order."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-rule-executions-matches-condition-evaluation-order"
GROUP = "ordering"
SERVICES = ["codepipeline"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListRuleExecutions returns exactly one Succeeded record per rule declared in the stage's
    beforeEntry condition."""
    cp = ctx.client("codepipeline")
    bucket = _create_artifact_bucket(ctx)
    role_arn = _create_pipeline_role(ctx, bucket)

    source_provider = ctx.unique_name("sim2real-cp-src-")
    build_provider = ctx.unique_name("sim2real-cp-bld-")
    _create_custom_action_type(ctx, "Source", source_provider, "1", 0, 0, 1, 1)
    _create_custom_action_type(ctx, "Build", build_provider, "1", 1, 1, 0, 1)

    pipeline_name = ctx.unique_name("sim2real-cp-pipe-")
    pipeline = {
        "name": pipeline_name,
        "roleArn": role_arn,
        "pipelineType": "V2",
        "artifactStore": {"type": "S3", "location": bucket},
        "stages": [
            {
                "name": "Source",
                "actions": [{
                    "name": "SourceAction",
                    "actionTypeId": {"category": "Source", "owner": "Custom", "provider": source_provider, "version": "1"},
                    "outputArtifacts": [{"name": "SourceOutput"}],
                    "namespace": "SrcVars",
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
                "beforeEntry": {
                    "conditions": [{
                        "result": "SKIP",
                        "rules": [
                            {
                                "name": "RuleAlpha",
                                "ruleTypeId": {"category": "Rule", "owner": "AWS", "provider": "VariableCheck", "version": "1"},
                                "configuration": {
                                    "Variable": "#{SrcVars.RepoName}",
                                    "Value": "MyDemoRepo",
                                    "Operator": "EQ",
                                },
                                "inputArtifacts": [],
                            },
                            {
                                "name": "RuleBeta",
                                "ruleTypeId": {"category": "Rule", "owner": "AWS", "provider": "VariableCheck", "version": "1"},
                                "configuration": {
                                    "Variable": "#{SrcVars.RepoName}",
                                    "Value": "Demo",
                                    "Operator": "CONTAINS",
                                },
                                "inputArtifacts": [],
                            },
                        ],
                    }],
                },
            },
        ],
    }
    _create_pipeline_with_role_propagation_retry(ctx, cp, pipeline, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=pipeline_name))

    # CreatePipeline auto-triggers its own initial execution; calling StartPipelineExecution
    # again would just queue a second, superseded execution racing the one CreatePipeline
    # already started, and PollForJobs could hand back either one's job indiscriminately.
    # Track the execution CreatePipeline actually started, and filter the job to match it.
    exec_id = _poll_for_execution_id(ctx, pipeline_name)
    source_job = _poll_one_job_for_execution(
        ctx,
        {"category": "Source", "owner": "Custom", "provider": source_provider, "version": "1"},
        exec_id,
    )
    _ack_and_succeed(ctx, source_job, output_variables={"RepoName": "MyDemoRepo"})

    # GetPipelineState reflects the live rule/condition evaluation near-instantly; use it to
    # confirm the rules genuinely ran before relying on ListRuleExecutions, which is a
    # historical-record API with a much longer eventual-consistency lag.
    _poll_until_condition_state_terminal(ctx, pipeline_name, exec_id, "Build", timeout_s=180.0, interval_s=4.0)

    rule_details = _poll_until_rule_count(ctx, pipeline_name, exec_id, 2, timeout_s=300.0, interval_s=6.0)
    by_name = {r["ruleName"]: r for r in rule_details}
    declared_rule_names = [
        r["name"] for r in pipeline["stages"][1]["beforeEntry"]["conditions"][0]["rules"]
    ]
    assert set(by_name) == set(declared_rule_names), set(by_name)
    statuses = {name: r["status"] for name, r in by_name.items()}
    assert statuses == {name: "Succeeded" for name in declared_rule_names}, statuses
    # A condition's rules "are evaluated together" and ListRuleExecutions documents no order,
    # so neither startTime order nor list order is asserted; each rule appears exactly once.
    returned_names = [r["ruleName"] for r in rule_details]
    assert sorted(returned_names) == sorted(declared_rule_names), returned_names



def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-art-").lower().replace("_", "-")[:63]
    kwargs = {"Bucket": bucket}
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


def _create_pipeline_with_role_propagation_retry(ctx, cp, pipeline, tags, timeout_s=30.0, interval_s=2.0):
    # IAM role trust policies can take a few seconds to propagate before CodePipeline can
    # validate the role; retry only that specific, transient rejection.
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            cp.create_pipeline(pipeline=pipeline, tags=tags)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("InvalidStructureException", "ValidationException"):
                last_err = exc
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"could not create pipeline after IAM role propagation window: {last_err}")


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


def _poll_for_execution_id(ctx, pipeline_name, timeout_s=90.0, interval_s=2.0):
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        execs = cp.list_pipeline_executions(pipelineName=pipeline_name).get("pipelineExecutionSummaries", [])
        if execs:
            return execs[0]["pipelineExecutionId"]
        time.sleep(interval_s)
    raise AssertionError(f"no execution ever appeared for pipeline {pipeline_name} within {timeout_s}s")


def _poll_one_job_for_execution(ctx, action_type_id, execution_id, timeout_s=90.0, interval_s=3.0):
    # CreatePipeline's auto-triggered execution is not the only thing that can produce a
    # job for this actionTypeId, so match the job to the execution this check is tracking
    # rather than accepting whichever job PollForJobs hands back first.
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        jobs = cp.poll_for_jobs(actionTypeId=action_type_id, maxBatchSize=10).get("jobs", [])
        for job in jobs:
            if job.get("data", {}).get("pipelineContext", {}).get("pipelineExecutionId") == execution_id:
                return job
        time.sleep(interval_s)
    raise AssertionError(f"no job for execution {execution_id} appeared for actionTypeId={action_type_id} within {timeout_s}s")


def _ack_and_succeed(ctx, job, output_variables=None):
    cp = ctx.client("codepipeline")
    cp.acknowledge_job(jobId=job["id"], nonce=job["nonce"])
    kwargs = {"jobId": job["id"]}
    if output_variables:
        kwargs["outputVariables"] = output_variables
    cp.put_job_success_result(**kwargs)


_RULE_TERMINAL_STATUSES = ("Succeeded", "Abandoned", "Failed")


def _poll_until_rule_count(ctx, pipeline_name, exec_id, count, timeout_s=90.0, interval_s=3.0):
    # ListRuleExecutions is a historical-record API with its own eventual-consistency lag,
    # separate from (and slower than) GetPipelineState's aggregate condition status: a
    # record can appear here, at count, while still reporting InProgress. Wait for every
    # record to reach its own terminal status, not just for the count to be met.
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    details = []
    while time.monotonic() < deadline:
        resp = cp.list_rule_executions(
            pipelineName=pipeline_name, filter={"pipelineExecutionId": exec_id}, maxResults=100
        )
        details = resp.get("ruleExecutionDetails", [])
        if len(details) >= count and all(d["status"] in _RULE_TERMINAL_STATUSES for d in details):
            return details
        time.sleep(interval_s)
    statuses = {d["ruleName"]: d["status"] for d in details}
    raise AssertionError(
        f"expected {count} terminal rule executions within {timeout_s}s, saw {statuses}"
    )


_CONDITION_TERMINAL_STATUSES = ("Succeeded", "Failed", "Errored", "Cancelled", "Abandoned", "Overridden")


def _poll_until_condition_state_terminal(ctx, pipeline_name, exec_id, stage_name, timeout_s=90.0, interval_s=3.0):
    # beforeEntryConditionState carries no top-level latestExecution: the condition's own
    # run status is nested one level deeper, under conditionStates[0].latestExecution.
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        resp = cp.get_pipeline_state(name=pipeline_name)
        for stage in resp.get("stageStates", []):
            if stage["stageName"] != stage_name:
                continue
            cond_states = stage.get("beforeEntryConditionState", {}).get("conditionStates", [])
            if cond_states:
                status = cond_states[0].get("latestExecution", {}).get("status")
        if status in _CONDITION_TERMINAL_STATUSES:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"{stage_name} beforeEntry condition never reached a terminal state via GetPipelineState, last seen {status}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
