"""lambda-bedrock-agent-invoke-agent-missing-permission-negative."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-bedrock-agent-invoke-agent-missing-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["bedrock-agent", "lambda", "opensearchserverless"]


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """InvokeAgent on a valid but nonexistent agent answers AccessDeniedException to a Lambda whose role lacks
    bedrock:InvokeAgent and ResourceNotFoundException to one whose role grants it, with no completion either way:
    authorization runs before the agent lookup."""
    fake_agent_id = "zzzzzzzzz9"
    fake_alias_id = "zzzzzzzz88"

    denied_role_arn, _ = _create_role(
        ctx,
        [],
        "sim2real-lambdadenied-",
        managed_policy_arn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )
    denied_fn = _create_lambda(ctx, denied_role_arn, _INVOKE_AGENT_HANDLER)
    denied_body = _invoke(
        ctx,
        denied_fn,
        {
            "region": ctx.region,
            "agent_id": fake_agent_id,
            "agent_alias_id": fake_alias_id,
            "session_id": str(uuid.uuid4()),
            "input_text": "Reply with exactly the single word: mango.",
        },
    )
    assert denied_body["ok"] is False, denied_body
    assert denied_body["code"] == "AccessDeniedException", denied_body
    assert "completion" not in denied_body, denied_body

    allowed_role_arn, _ = _create_role(
        ctx,
        [{"Effect": "Allow", "Action": "bedrock:InvokeAgent", "Resource": "*"}],
        "sim2real-lambdaallowed-",
        managed_policy_arn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )
    allowed_fn = _create_lambda(ctx, allowed_role_arn, _INVOKE_AGENT_HANDLER)
    allowed_body = _invoke(
        ctx,
        allowed_fn,
        {
            "region": ctx.region,
            "agent_id": fake_agent_id,
            "agent_alias_id": fake_alias_id,
            "session_id": str(uuid.uuid4()),
            "input_text": "Reply with exactly the single word: mango.",
        },
    )
    assert allowed_body["ok"] is False, allowed_body
    assert allowed_body["code"] == "ResourceNotFoundException", allowed_body
    assert "completion" not in allowed_body, allowed_body


_INVOKE_AGENT_HANDLER = """
import boto3

def handler(event, context):
    client = boto3.client("bedrock-agent-runtime", region_name=event["region"])
    try:
        resp = client.invoke_agent(
            agentId=event["agent_id"],
            agentAliasId=event["agent_alias_id"],
            sessionId=event["session_id"],
            inputText=event["input_text"],
        )
        completion = ""
        for ev in resp["completion"]:
            if "chunk" in ev:
                completion += ev["chunk"]["bytes"].decode("utf-8")
        return {"ok": True, "completion": completion}
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "response", {}).get("Error", {}).get("Code", type(e).__name__)
        return {"ok": False, "code": code}
"""

_LAMBDA_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
})


def _create_role(ctx, inline_statements, name_prefix, managed_policy_arn=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name(name_prefix)
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_LAMBDA_TRUST,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]

    def _cleanup():
        if managed_policy_arn:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="inline")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    if managed_policy_arn:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
    if inline_statements:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="inline",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": inline_statements}),
        )
    return role["Arn"], role_name


def _zip_code(src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", src)
    return buf.getvalue()


def _create_lambda(ctx, role_arn, src, env=None, timeout=60):
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-lambda-fn-")
    zip_bytes = _zip_code(src)
    deadline = time.monotonic() + 90
    last_err: Any = None
    created = False
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Environment={"Variables": env or {}},
                Tags={"sim2real": CHECK},
            )
            created = True
            break
        except lam.exceptions.InvalidParameterValueException as err:
            last_err = err
            time.sleep(5)
    if not created:
        raise AssertionError(f"lambda role never became assumable: {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    lam.get_waiter("function_active_v2").wait(FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return fn_name


def _invoke(ctx, fn_name, payload):
    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=fn_name, Payload=json.dumps(payload).encode())
    raw = resp["Payload"].read()
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invocation errored: {raw!r}")
    return json.loads(raw)


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

