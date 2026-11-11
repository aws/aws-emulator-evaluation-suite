"""lambda-bedrock-agent-missing-invokeagent-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-bedrock-agent-missing-invokeagent-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["bedrock-agent-runtime", "lambda", "s3vectors"]

# A syntactically valid AgentId/AgentAliasId (pattern ^[0-9a-zA-Z]+$, max length 10) that names no
# real resource. The check needs no real agent, since it exercises only the InvokeAgent
# permission boundary.
FAKE_AGENT_ID = "ABCD123456"
FAKE_ALIAS_ID = "ABCDEFGHIJ"

LAMBDA_CODE = """
import json
import boto3

def handler(event, context):
    client = boto3.client("bedrock-agent-runtime")
    try:
        resp = client.invoke_agent(
            agentId=event["agentId"],
            agentAliasId=event["agentAliasId"],
            sessionId=event["sessionId"],
            inputText=event["inputText"],
        )
        text_parts = []
        for ev in resp["completion"]:
            if "chunk" in ev:
                text_parts.append(ev["chunk"]["bytes"].decode("utf-8"))
        return {"ok": True, "answer": "".join(text_parts)}
    except Exception as e:
        error = getattr(e, "response", {}).get("Error", {})
        code = error.get("Code", type(e).__name__)
        return {"ok": False, "error_code": code, "error_message": error.get("Message", str(e))}
"""


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda role lacking bedrock:InvokeAgent gets AccessDeniedException from InvokeAgent on a
    nonexistent alias, while an otherwise identical role that has it gets ResourceNotFoundException:
    authorization runs before, and independently of, resolving the agent/alias."""
    # Deny role: no bedrock permission at all (only log write, for basic Lambda execution).
    deny_role_arn = _create_role(
        ctx,
        "lambda.amazonaws.com",
        [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            }
        ],
    )
    deny_fn = _create_lambda(ctx, deny_role_arn, LAMBDA_CODE)

    # Allow role: same setup plus bedrock:InvokeAgent -- the in-file positive control.
    allow_role_arn = _create_role(
        ctx,
        "lambda.amazonaws.com",
        [
            {"Effect": "Allow", "Action": "bedrock:InvokeAgent", "Resource": "*"},
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            },
        ],
    )
    allow_fn = _create_lambda(ctx, allow_role_arn, LAMBDA_CODE)

    invoke_args = {
        "agentId": FAKE_AGENT_ID,
        "agentAliasId": FAKE_ALIAS_ID,
        "sessionId": ctx.unique_name("sess-"),
        "inputText": "ping",
    }

    account = deny_role_arn.split(":")[4]
    deny_role_name = deny_role_arn.split("/")[-1]
    alias_arn = f"arn:aws:bedrock:{ctx.region}:{account}:agent-alias/{FAKE_AGENT_ID}/{FAKE_ALIAS_ID}"

    denied = _invoke_lambda_json(ctx, deny_fn, invoke_args)
    assert denied["ok"] is False, denied
    assert denied["error_code"] == "AccessDeniedException", denied
    # Lambda's execution session is named after the function.
    assert denied["error_message"] == (
        f"User: arn:aws:sts::{account}:assumed-role/{deny_role_name}/{deny_fn} is not authorized "
        f"to perform: bedrock:InvokeAgent on resource: {alias_arn} because no identity-based "
        "policy allows the bedrock:InvokeAgent action"
    ), (
        f"unexpected AccessDeniedException message {denied!r}"
    )

    allowed = _invoke_lambda_json(ctx, allow_fn, invoke_args)
    assert allowed["ok"] is False, allowed
    assert allowed["error_code"] == "ResourceNotFoundException", allowed
    assert allowed["error_message"] == (
        "Failed to retrieve resource because it doesn't exist. "
        "Retry the request with a different resource identifier."
    ), f"unexpected ResourceNotFoundException message {allowed!r}"


# ===== helpers =====


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_role(ctx, trust_service: str, statements: list) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name,
        PolicyName="inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
    return role_arn


def _create_lambda(ctx, role_arn: str, code: str, timeout: int = 60) -> str:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-fn-")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    ctx.on_cleanup(lambda: _delete_lambda_log_group(ctx, name))
    # Until IAM propagates the new role, CreateFunction answers InvalidParameterValueException
    # "... cannot be assumed by Lambda"; retry exactly that, polling to a deadline.
    deadline = time.monotonic() + 75.0
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, time.monotonic() + max(1.0, left - 5.0))
    while True:
        try:
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": buf.getvalue()},
                Timeout=timeout,
                MemorySize=256,
            )
            break
        except lam.exceptions.InvalidParameterValueException as e:
            if "cannot be assumed" not in str(e) or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function(FunctionName=name)["Configuration"]["State"],
        lambda s: s == "Active",
        timeout_s=90,
        interval_s=3,
    )
    return name


def _invoke_lambda_json(ctx, name: str, payload: dict) -> dict:
    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=name, InvocationType="RequestResponse", Payload=json.dumps(payload).encode())
    body = json.loads(resp["Payload"].read())
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda function error: {body}")
    return body


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
