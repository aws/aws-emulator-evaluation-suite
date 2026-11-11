"""lambda-bedrock-agent-invoke-agent-wrong-agent-id-negative."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-bedrock-agent-invoke-agent-wrong-agent-id-negative"
GROUP = "arn-resolution"
SERVICES = ["bedrock-agent", "lambda", "opensearchserverless"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """InvokeAgent from a Lambda whose role grants bedrock:InvokeAgent answers ValidationException for a malformed
    agentId and ResourceNotFoundException for a valid but nonexistent one (Agents Classic creates no new agents),
    with no completion either way: id validation and lookup are distinct failures."""
    lambda_role_arn, _ = _create_role(
        ctx,
        [{"Effect": "Allow", "Action": "bedrock:InvokeAgent", "Resource": "*"}],
        "sim2real-lambdarole-",
        managed_policy_arn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )
    fn_name = _create_lambda(ctx, lambda_role_arn, _INVOKE_AGENT_HANDLER)

    # Malformed agentId: too short / wrong charset for the required 10-char pattern.
    malformed_body = _invoke(
        ctx,
        fn_name,
        {
            "region": ctx.region,
            "agent_id": "not-a-valid-id!!",
            "agent_alias_id": "zzzzzzzz88",
            "session_id": str(uuid.uuid4()),
            "input_text": "Reply with exactly the single word: kiwi.",
        },
    )
    assert malformed_body["ok"] is False, malformed_body
    assert malformed_body["code"] == "ValidationException", malformed_body
    assert "completion" not in malformed_body, malformed_body

    # Syntactically valid but nonexistent agentId.
    bogus_body = _invoke(
        ctx,
        fn_name,
        {
            "region": ctx.region,
            "agent_id": "zzzzzzzzz9",
            "agent_alias_id": "zzzzzzzz88",
            "session_id": str(uuid.uuid4()),
            "input_text": "Reply with exactly the single word: kiwi.",
        },
    )
    assert bogus_body["ok"] is False, bogus_body
    assert bogus_body["code"] == "ResourceNotFoundException", bogus_body
    assert "completion" not in bogus_body, bogus_body


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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
                Tags={"sim2real:managed": "true"},
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

