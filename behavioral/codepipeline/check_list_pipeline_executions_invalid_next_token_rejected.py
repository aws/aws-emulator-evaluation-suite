"""list-pipeline-executions-invalid-next-token-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-pipeline-executions-invalid-next-token-rejected"
GROUP = "error-semantics"
SERVICES = ["codepipeline"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListPipelineExecutions rejects a corrupted/foreign nextToken with InvalidNextTokenException
    instead of silently returning an empty or wrong page, while a normal call (no token) still
    succeeds."""
    cp = ctx.client("codepipeline")
    role_arn = _cp_create_role(ctx)
    bucket = _cp_create_bucket(ctx)
    provider = _cp_create_custom_source_type(ctx)
    pipeline = _cp_create_pipeline(ctx, role_arn, bucket, provider)

    # give it one real execution so the pipeline has genuine history to page over
    cp.start_pipeline_execution(name=pipeline)

    # positive control: a normal, unpaginated call succeeds -- poll briefly since the
    # execution record can lag StartPipelineExecution by a moment
    resp = _wait_for_executions(ctx, pipeline, min_count=1)
    assert "pipelineExecutionSummaries" in resp, f"positive control missing key entirely: {resp!r}"
    assert len(resp["pipelineExecutionSummaries"]) >= 1, (
        f"expected at least 1 execution after StartPipelineExecution, got {resp['pipelineExecutionSummaries']!r}"
    )

    bogus_token = "not-a-real-token=="
    refusal = _error_code(
        lambda: cp.list_pipeline_executions(pipelineName=pipeline, nextToken=bogus_token)
    )
    assert refusal == (
        "InvalidNextTokenException",
        f"The nextToken value '{bogus_token}' is not valid. Specify a valid nextToken value, and then try again.",
    ), refusal

    # effect absent: the bogus token did not corrupt subsequent, valid listing
    resp2 = cp.list_pipeline_executions(pipelineName=pipeline)
    assert len(resp2["pipelineExecutionSummaries"]) == len(resp["pipelineExecutionSummaries"]), (
        f"expected {len(resp['pipelineExecutionSummaries'])} executions after the rejected call, "
        f"got {len(resp2['pipelineExecutionSummaries'])}"
    )


def _error_code(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected SUCCESS raises, because
    an emulator ACCEPTING a bogus nextToken that real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected InvalidNextTokenException, but the call SUCCEEDED and returned {result!r}")


def _wait_for_executions(ctx, pipeline_name, min_count=1, timeout_s=60):
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    resp = {"pipelineExecutionSummaries": []}
    while time.monotonic() < deadline:
        resp = cp.list_pipeline_executions(pipelineName=pipeline_name)
        if len(resp.get("pipelineExecutionSummaries", [])) >= min_count:
            return resp
        time.sleep(2)
    return resp


def _cp_create_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codepipeline.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"}]}
    iam.put_role_policy(RoleName=role_name, PolicyName="cp-access", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="cp-access"))
    iam.get_waiter("role_exists").wait(RoleName=role_name, WaiterConfig={"Delay": 2, "MaxAttempts": 10})
    return role_arn


def _cp_create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-art-").lower().replace("_", "-")
    # us-east-1 rejects an explicit LocationConstraint matching the default region; the
    # bucket still lands in ctx.region either way, so this is not a region pin on the check.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    return bucket


def _cp_create_custom_source_type(ctx) -> str:
    cp = ctx.client("codepipeline")
    provider = ctx.unique_name("cpsrc-")[:25]
    cp.create_custom_action_type(
        category="Source",
        provider=provider,
        version="1",
        inputArtifactDetails={"minimumCount": 0, "maximumCount": 0},
        outputArtifactDetails={"minimumCount": 1, "maximumCount": 1},
    )
    ctx.on_cleanup(lambda: cp.delete_custom_action_type(category="Source", provider=provider, version="1"))
    return provider


def _cp_create_pipeline(ctx, role_arn, bucket, provider, extra_stages=None) -> str:
    cp = ctx.client("codepipeline")
    name = ctx.unique_name("sim2real-cp-pipe-")
    stages = [
        {
            "name": "Source",
            "actions": [
                {
                    "name": "SourceAction",
                    "actionTypeId": {"category": "Source", "owner": "Custom", "provider": provider, "version": "1"},
                    "outputArtifacts": [{"name": "SourceOutput"}],
                }
            ],
        }
    ]
    if extra_stages:
        stages.extend(extra_stages)
    else:
        # CodePipeline requires a minimum of 2 stages.
        stages.append(
            {
                "name": "Approval",
                "actions": [
                    {
                        "name": "ApprovalAction",
                        "actionTypeId": {
                            "category": "Approval",
                            "owner": "AWS",
                            "provider": "Manual",
                            "version": "1",
                        },
                    }
                ],
            }
        )
    deadline = time.monotonic() + 30
    last_exc = None
    while time.monotonic() < deadline:
        try:
            cp.create_pipeline(
                pipeline={
                    "name": name,
                    "roleArn": role_arn,
                    "artifactStore": {"type": "S3", "location": bucket},
                    "stages": stages,
                }
            )
            break
        except ClientError as exc:
            last_exc = exc
            time.sleep(3)
    else:
        raise last_exc
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
