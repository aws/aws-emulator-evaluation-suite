"""cli-iot-topic-rule-list-and-describe-roundtrip."""
from __future__ import annotations

import io
import json
import os
import subprocess
import tempfile
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from fidelity_tests_runner import require_tools
from botocore.exceptions import ClientError

CHECK = "cli-iot-topic-rule-list-and-describe-roundtrip"
GROUP = "cli-roundtrip"
SERVICES = ["iot", "lambda"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A disabled topic rule with a description and a lambda action, created through the CLI, round-trips exactly
    through list-topic-rules and get-topic-rule: ARN, disabled flag, description, topic and functionArn."""
    require_tools("aws")

    _, func_arn = _create_forwarding_function(ctx)

    topic = ctx.unique_name("sim2real-iotlamcli-ld-") + "/data"
    rule_name = _rule_name(ctx, "listdesc")
    description = f"sim2real-marker-{rule_name}"
    rule_arn = _cli_create_topic_rule(
        ctx,
        rule_name,
        sql=f"SELECT * FROM '{topic}'",
        actions=[{"lambda": {"functionArn": func_arn}}],
        rule_disabled=True,
        description=description,
    )

    got = _run_aws(ctx, "iot", "get-topic-rule", "--rule-name", rule_name)
    assert got["ruleArn"] == rule_arn, f"get-topic-rule ruleArn mismatch: expected {rule_arn}, got {got['ruleArn']!r}"
    rule = got["rule"]
    assert rule["ruleDisabled"] is True, f"expected ruleDisabled=True, got {rule['ruleDisabled']!r}"
    assert rule["description"] == description, (
        f"expected description {description!r}, got {rule['description']!r}"
    )
    assert rule["actions"][0]["lambda"]["functionArn"] == func_arn, (
        f"expected lambda functionArn {func_arn!r}, got {rule['actions'][0]['lambda']['functionArn']!r}"
    )

    listed = _run_aws(ctx, "iot", "list-topic-rules")
    matches = [r for r in listed.get("rules", []) if r["ruleName"] == rule_name]
    assert len(matches) == 1, f"expected exactly one listed rule named {rule_name}, got {matches!r}"
    item = matches[0]
    assert item["ruleArn"] == rule_arn, f"list-topic-rules ruleArn mismatch: expected {rule_arn}, got {item['ruleArn']!r}"
    assert item["ruleDisabled"] is True, f"list-topic-rules expected ruleDisabled=True, got {item['ruleDisabled']!r}"
    assert item["topicPattern"] == topic, f"expected topicPattern {topic!r}, got {item['topicPattern']!r}"


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


_FORWARD_LAMBDA_CODE = """
import json


def handler(event, context):
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy))
    return role_arn


def _create_forwarding_function(ctx) -> tuple[str, str]:
    lam = ctx.client("lambda")
    role_arn = _create_lambda_role(ctx)
    func_name = ctx.unique_name("sim2real-iotlamcli-fwd-")
    zip_bytes = _zip_bytes(_FORWARD_LAMBDA_CODE)
    fn = _retry_on_role_propagation(
        lambda: lam.create_function(
            FunctionName=func_name,
            Runtime="python3.12",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": zip_bytes},
            Timeout=15,
            Tags={"sim2real": CHECK},
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


def _rule_name(ctx, kind: str) -> str:
    raw = ctx.unique_name(f"sim2real_iotlamcli_{kind}_")
    return "".join(c if (c.isalnum() or c == "_") else "_" for c in raw)


def _cli_create_topic_rule(
    ctx,
    rule_name: str,
    sql: str,
    actions: list[dict],
    rule_disabled: bool = False,
    description: str | None = None,
) -> str:
    payload: dict[str, Any] = {
        "sql": sql,
        "awsIotSqlVersion": "2016-03-23",
        "actions": actions,
        "ruleDisabled": rule_disabled,
    }
    if description is not None:
        payload["description"] = description
    _run_aws(
        ctx,
        "iot",
        "create-topic-rule",
        "--rule-name",
        rule_name,
        "--topic-rule-payload",
        json.dumps(payload),
        "--tags",
        f"sim2real={CHECK}",
    )
    ctx.on_cleanup(lambda: _run_aws(ctx, "iot", "delete-topic-rule", "--rule-name", rule_name, check=False))
    return f"arn:aws:iot:{ctx.region}:{_account_id(ctx)}:rule/{rule_name}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
