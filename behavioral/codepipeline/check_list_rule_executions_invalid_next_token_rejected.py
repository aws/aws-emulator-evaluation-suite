"""list-rule-executions-invalid-next-token-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-rule-executions-invalid-next-token-rejected"
GROUP = "error-semantics"
SERVICES = ["codepipeline"]

_SCENARIO = "codepipeline-list-rule-executions-invalid-next-token"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListRuleExecutions without a token returns an empty list for a pipeline with no condition rules, while a
    garbage nextToken fails with InvalidNextTokenException and its exact message rather than returning a page.
    """
    cp = ctx.client("codepipeline")
    bucket = _artifact_bucket(ctx)
    role_arn = _pipeline_role(ctx, bucket)

    pipeline_name = ctx.unique_name("sim2real-cp-token-")
    stages = [_source_stage(bucket, "source/source.zip"), _approval_stage()]
    _create_pipeline(ctx, pipeline_name, role_arn, bucket, stages)

    # positive control: a well-formed call succeeds
    good = cp.list_rule_executions(pipelineName=pipeline_name)
    assert good["ruleExecutionDetails"] == [], f"expected no rule executions, got {good['ruleExecutionDetails']!r}"

    # negative: garbage token is rejected outright
    bogus_token = "not-a-real-token=="
    refusal = _error_code(lambda: cp.list_rule_executions(pipelineName=pipeline_name, nextToken=bogus_token))
    assert refusal == (
        "InvalidNextTokenException",
        f"The nextToken value '{bogus_token}' is not valid. Specify a valid nextToken value, and then try again.",
    ), refusal

    # effect absent: a subsequent well-formed call still behaves exactly as before
    still_good = cp.list_rule_executions(pipelineName=pipeline_name)
    assert still_good["ruleExecutionDetails"] == [], (
        f"bogus nextToken corrupted subsequent listing, got {still_good['ruleExecutionDetails']!r}"
    )


def _error_code(fn):
    """Return (code, message) of the expected refusal; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a refusal, but the call succeeded: {result!r}")


def _artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-art-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": _SCENARIO}]})
    return bucket


def _pipeline_role(ctx, bucket) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codepipeline.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="sim2real-inline", PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-inline"))
    return role_arn


def _source_stage(bucket, key):
    return {
        "name": "Source",
        "actions": [
            {
                "name": "SourceAction",
                "actionTypeId": {"category": "Source", "owner": "AWS", "provider": "S3", "version": "1"},
                "outputArtifacts": [{"name": "SourceOutput"}],
                "configuration": {"S3Bucket": bucket, "S3ObjectKey": key, "PollForSourceChanges": "false"},
            }
        ],
    }


def _approval_stage():
    return {
        "name": "Approve",
        "actions": [
            {
                "name": "ApprovalAction",
                "actionTypeId": {"category": "Approval", "owner": "AWS", "provider": "Manual", "version": "1"},
            }
        ],
    }


def _create_pipeline(ctx, name, role_arn, bucket, stages, timeout_s=60.0):
    cp = ctx.client("codepipeline")
    decl = {"name": name, "roleArn": role_arn, "artifactStore": {"type": "S3", "location": bucket}, "stages": stages}
    pipeline_tags = [{"key": "sim2real", "value": _SCENARIO}]
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = cp.create_pipeline(pipeline=decl, tags=pipeline_tags)
            ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))
            return resp["pipeline"]
        except Exception as exc:  # IAM role/trust propagation is eventually consistent
            last_err = exc
            time.sleep(3)
    raise AssertionError(f"CreatePipeline never succeeded: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
