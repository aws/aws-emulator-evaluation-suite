"""create-model-invocation-job-without-permission-denied."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "create-model-invocation-job-without-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["bedrock"]

_SESSION_NAME = "sim2real-behavioral-check"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A role explicitly denied bedrock:CreateModelInvocationJob gets AccessDeniedException with the
    exact explicit-deny message and no job is listed, while the same role can still call
    ListFoundationModels, so the denial is scoped to the denied action."""
    iam = ctx.client("iam")
    bedrock = ctx.client("bedrock")
    account_id = ctx.account

    role_name = ctx.unique_name("sim2real-bedrock-deny-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            },
            {
                # CreateModelInvocationJob validates that roleArn's trust policy allows the
                # bedrock service to assume it (a batch-inference service role requirement)
                # *before* IAM authorization is evaluated -- without this statement the call
                # fails with ValidationException rather than exercising the permission denial
                # this check targets.
                "Effect": "Allow",
                "Principal": {"Service": "bedrock.amazonaws.com"},
                "Action": "sts:AssumeRole",
            },
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = f"{role_name}-policy"
    scoped_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "bedrock:ListFoundationModels", "Resource": "*"},
            {"Effect": "Deny", "Action": "bedrock:CreateModelInvocationJob", "Resource": "*"},
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(scoped_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    restricted_bedrock = _assume_role_client(ctx, role_arn, "bedrock")

    # Positive control: the same restricted principal can still call an action it was NOT
    # denied, proving the failure below is the specific deny, not a wholesale credentials issue.
    listed = restricted_bedrock.list_foundation_models()
    assert "modelSummaries" in listed, (
        f"expected the restricted principal's un-denied ListFoundationModels call to succeed "
        f"with a modelSummaries collection, got {listed!r}"
    )

    job_name = ctx.unique_name("sim2real-mij-")
    bucket_stub = ctx.unique_name("sim2real-mij-bucket")
    code, message = _error_code_and_message(
        lambda: restricted_bedrock.create_model_invocation_job(
            jobName=job_name,
            roleArn=role_arn,
            # A model ID that is actually on Bedrock's supported-batch-inference list (Titan
            # Express does not support batch inference at all, which triggers a ValidationException
            # for an "invalid model identifier" before IAM authorization is ever reached -- masking
            # the permission denial this check targets).
            modelId="meta.llama3-1-8b-instruct-v1:0",
            inputDataConfig={
                "s3InputDataConfig": {"s3Uri": f"s3://{bucket_stub}/input.jsonl"}
            },
            outputDataConfig={"s3OutputDataConfig": {"s3Uri": f"s3://{bucket_stub}/output/"}},
        )
    )
    assert code == "AccessDeniedException", (
        f"expected AccessDeniedException, got {code} ({message!r})"
    )
    expected_message = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{_SESSION_NAME} is not "
        f"authorized to perform: bedrock:CreateModelInvocationJob on resource: "
        f"arn:aws:bedrock:{ctx.region}:{account_id}:model-invocation-job/* with an explicit "
        f"deny in an identity-based policy"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the check's own credentials list no job under that name.
    jobs = bedrock.list_model_invocation_jobs(nameContains=job_name)
    assert jobs.get("invocationJobSummaries", []) == [], (
        f"expected no model invocation job to have been created, found {jobs}"
    )


def _error_code_and_message(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _assume_role_client(ctx, role_arn: str, service: str, timeout_s: float = 30.0):
    """Assume role and build a client, retrying briefly for the IAM trust to propagate."""
    from botocore.exceptions import ClientError

    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(
                RoleArn=role_arn, RoleSessionName=_SESSION_NAME
            )["Credentials"]
            return ctx.client(
                service,
                creds={
                    "aws_access_key_id": creds["AccessKeyId"],
                    "aws_secret_access_key": creds["SecretAccessKey"],
                    "aws_session_token": creds["SessionToken"],
                },
            )
        except ClientError as e:
            last_err = e
            time.sleep(2.0)
    raise AssertionError(f"could not assume role {role_arn} within {timeout_s}s: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
