"""cli-lambda-add-permission-wrong-principal-negative."""
from __future__ import annotations

import io
import json
import os
import subprocess
import tempfile
import time
import uuid
import zipfile
from typing import Any

from behavioral_harness import tags
from fidelity_tests_runner import require_tools
from botocore.exceptions import ClientError

CHECK = "cli-lambda-add-permission-wrong-principal-negative"
GROUP = "permission-boundary"
SERVICES = ["iot", "lambda"]


@tags("axis:negative-delivery", "cap:c3", "cap:c7", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """`aws lambda add-permission` accepts sns.amazonaws.com as the principal, but the IoT rules engine then never
    invokes the function on a matching publish; a correctly scoped iot.amazonaws.com statement delivers."""
    require_tools("aws")

    queue_url = _create_queue(ctx)
    func_name, func_arn = _create_forwarding_function(ctx, queue_url)

    topic = ctx.unique_name("sim2real-iotlamcli-wp-") + "/data"
    rule_name = _rule_name(ctx, "wrongprincipal")
    rule_arn = _cli_create_topic_rule(
        ctx, rule_name, sql=f"SELECT * FROM '{topic}'", actions=[{"lambda": {"functionArn": func_arn}}]
    )
    _cli_add_permission(ctx, func_name, rule_arn, "sns.amazonaws.com", "wrongprincipal")

    marker_bad = str(uuid.uuid4())
    _publish(ctx, topic, {"marker": marker_bad})
    seen_bad = _collect_for(ctx, queue_url, duration_s=35.0)
    assert not any(m.get("marker") == marker_bad for m in seen_bad), (
        "publish invoked the function despite the resource policy granting only sns.amazonaws.com"
    )

    _cli_add_permission(ctx, func_name, rule_arn, "iot.amazonaws.com", "correctprincipal")

    marker_good = str(uuid.uuid4())
    _publish(ctx, topic, {"marker": marker_good})
    seen_good = _wait_for_message(ctx, queue_url, lambda m: m.get("marker") == marker_good, timeout_s=90)
    assert any(m.get("marker") == marker_good for m in seen_good), (
        "positive control (correct iot.amazonaws.com principal) never invoked the function"
    )


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command,
        shell=isinstance(command, str),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


def _run_script(ctx, script: str, *, timeout_s=120.0, check=True, env_extra=None):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
        f.write("#!/bin/bash\nset -euo pipefail\n")
        f.write(script)
        script_path = f.name
    try:
        os.chmod(script_path, 0o755)
        return _run_shell(ctx, ["bash", script_path], timeout_s=timeout_s, check=check, env_extra=env_extra)
    finally:
        os.unlink(script_path)


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    proc = _run_shell(
        ctx, ["aws", "--output", "json", *args], env_extra={"AWS_PAGER": ""}, timeout_s=timeout_s, check=check
    )
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _wait_for_effect(probe, predicate, timeout_s=120.0, interval_s=2.0, description="effect"):
    return _poll_until(probe, predicate, timeout_s=timeout_s, interval_s=interval_s, description=description)


def _retry_on_role_propagation(fn, retry_codes, timeout_s=45.0, interval_s=3.0, description="operation"):
    def probe():
        try:
            return ("ok", fn())
        except ClientError as exc:
            if exc.response["Error"]["Code"] in retry_codes:
                return ("retry", None)
            raise

    _, result = _poll_until(
        probe, lambda r: r[0] == "ok", timeout_s=timeout_s, interval_s=interval_s, description=description
    )
    return result


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _iot_data_client(ctx):
    iot = ctx.client("iot")
    endpoint = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    return ctx.client("iot-data", endpoint_url=ctx.endpoint_url(endpoint))


_FORWARD_LAMBDA_CODE = """
import json
import os
import boto3

_sqs = boto3.client("sqs")


def handler(event, context):
    _sqs.send_message(
        QueueUrl=os.environ["FORWARD_QUEUE_URL"],
        MessageBody=json.dumps(event, default=str),
    )
    return {"forwarded": True}
"""


def _zip_bytes(code: str, filename: str = "index.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, code)
    return buf.getvalue()


def _create_lambda_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-iotlamcli-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sqs-send",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": "*"}]}
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sqs-send"))
    return role_arn


def _create_forwarding_function(ctx, queue_url: str) -> tuple[str, str]:
    lam = ctx.client("lambda")
    role_arn = _create_lambda_role(ctx)
    func_name = ctx.unique_name("sim2real-iotlamcli-fwd-")
    zip_bytes = _zip_bytes(_FORWARD_LAMBDA_CODE)
    ctx.on_cleanup(lambda _n=func_name: _delete_lambda_log_group(ctx, _n))
    fn = _retry_on_role_propagation(
        lambda: lam.create_function(
            FunctionName=func_name,
            Runtime="python3.12",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": zip_bytes},
            Environment={"Variables": {"FORWARD_QUEUE_URL": queue_url}},
            Timeout=30,
            Tags={"sim2real:managed": "true"},
        ),
        retry_codes={"InvalidParameterValueException"},
        description=f"lambda function {func_name} create (role propagation)",
    )
    func_arn = fn["FunctionArn"]
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=func_name))
    _poll_until(
        lambda: lam.get_function(FunctionName=func_name)["Configuration"]["State"],
        lambda s: s == "Active",
        timeout_s=60,
        interval_s=2.0,
        description=f"function {func_name} Active",
    )
    return func_name, func_arn


def _create_queue(ctx) -> str:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-iotlamcli-q-"), tags={"sim2real:managed": "true"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return url


def _rule_name(ctx, kind: str) -> str:
    raw = ctx.unique_name(f"sim2real_iotlamcli_{kind}_")
    return "".join(c if (c.isalnum() or c == "_") else "_" for c in raw)


def _cli_create_topic_rule(ctx, rule_name: str, sql: str, actions: list[dict], rule_disabled: bool = False) -> str:
    payload: dict[str, Any] = {
        "sql": sql,
        "awsIotSqlVersion": "2016-03-23",
        "actions": actions,
        "ruleDisabled": rule_disabled,
    }
    _run_aws(
        ctx,
        "iot",
        "create-topic-rule",
        "--rule-name",
        rule_name,
        "--topic-rule-payload",
        json.dumps(payload),
        "--tags",
        "sim2real:managed=true",
    )
    ctx.on_cleanup(lambda: _run_aws(ctx, "iot", "delete-topic-rule", "--rule-name", rule_name, check=False))
    return f"arn:aws:iot:{ctx.region}:{_account_id(ctx)}:rule/{rule_name}"


def _cli_add_permission(ctx, function_name: str, source_arn: str, principal: str, sid_hint: str) -> None:
    lam = ctx.client("lambda")
    sid = "".join(c if c.isalnum() else "-" for c in ctx.unique_name(f"sim2real-iotlamcli-perm-{sid_hint}-"))
    _run_aws(
        ctx,
        "lambda",
        "add-permission",
        "--function-name",
        function_name,
        "--statement-id",
        sid,
        "--action",
        "lambda:InvokeFunction",
        "--principal",
        principal,
        "--source-arn",
        source_arn,
    )
    ctx.on_cleanup(lambda: lam.remove_permission(FunctionName=function_name, StatementId=sid))


def _publish(ctx, topic: str, payload: dict) -> None:
    data = _iot_data_client(ctx)
    data.publish(topic=topic, qos=1, payload=json.dumps(payload).encode("utf-8"))


def _receive_once(ctx, queue_url: str, wait_s: int = 5) -> list[dict]:
    sqs = ctx.client("sqs")
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s)
    out = []
    for m in resp.get("Messages", []):
        try:
            out.append(json.loads(m["Body"]))
        except (ValueError, TypeError):
            out.append({"_raw": m["Body"]})
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    return out


def _wait_for_message(ctx, queue_url: str, predicate, timeout_s: float = 90.0) -> list[dict]:
    collected: list[dict] = []

    def probe():
        collected.extend(_receive_once(ctx, queue_url, wait_s=5))
        return collected

    _wait_for_effect(
        probe,
        lambda msgs: any(predicate(m) for m in msgs),
        timeout_s=timeout_s,
        interval_s=1.0,
        description="matching queue message",
    )
    return collected


def _collect_for(ctx, queue_url: str, duration_s: float = 30.0) -> list[dict]:
    deadline = time.monotonic() + duration_s
    out: list[dict] = []
    while time.monotonic() < deadline:
        out.extend(_receive_once(ctx, queue_url, wait_s=5))
    return out


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
