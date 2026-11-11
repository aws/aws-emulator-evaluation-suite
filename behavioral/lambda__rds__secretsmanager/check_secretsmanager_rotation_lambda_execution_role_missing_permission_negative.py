"""secretsmanager-rotation-lambda-execution-role-missing-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "secretsmanager-rotation-lambda-execution-role-missing-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["lambda", "rds", "secretsmanager"]


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-create-rule-schedule.html
@tags("axis:negative-delivery", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A scheduled rule invokes a rotation Lambda whose role lacks secretsmanager:PutSecretValue,
    and the secret keeps its value; adding that permission to the role lets the same schedule
    rotate it."""
    secretsmanager = ctx.client("secretsmanager")
    events = ctx.client("events")
    lam = ctx.client("lambda")
    iam = ctx.client("iam")

    secret_name = ctx.unique_name("sim2real-sm-rolerot-")
    initial_value = f"initial-{secret_name}"
    secret_arn = secretsmanager.create_secret(
        Name=secret_name,
        SecretString=initial_value,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["ARN"]
    ctx.on_cleanup(
        lambda: secretsmanager.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True)
    )

    # Execution role WITHOUT any secretsmanager permission -- only basic CloudWatch Logs access.
    role_name, role_arn = _create_lambda_role(ctx, [])

    function_name = ctx.unique_name("sim2real-sm-rolefn-")
    function_arn = _create_function(
        ctx, function_name, role_arn, _ROTATION_HANDLER_CODE, env={"SECRET_ID": secret_arn}
    )

    rule_name = ctx.unique_name("sim2real-sm-rolerule-")
    rule_arn = events.put_rule(
        Name=rule_name,
        ScheduleExpression="rate(1 minute)",
        State="ENABLED",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    events.put_targets(
        Rule=rule_name,
        Targets=[
            {"Id": "rotation-lambda", "Arn": function_arn, "Input": json.dumps({"SecretId": secret_arn})}
        ],
    )
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["rotation-lambda"]))

    lam.add_permission(
        FunctionName=function_name,
        StatementId="allow-eventbridge-invoke",
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule_arn,
    )

    def _current_value() -> str:
        return secretsmanager.get_secret_value(SecretId=secret_arn)["SecretString"]

    # Effect-absent: the function is invoked on schedule but its PutSecretValue call is denied
    # by its own execution role, so the secret must never change.
    deadline = time.monotonic() + 130.0
    while time.monotonic() < deadline:
        assert _current_value() == initial_value, "secret rotated despite missing execution-role permission"
        time.sleep(5.0)

    # Positive control: grant the missing execution-role permission (a distinct boundary from
    # the resource-policy statement already present) and confirm the identical schedule now
    # rotates the secret.
    policy_name = f"{role_name}-secretsmanager-write"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["secretsmanager:PutSecretValue", "secretsmanager:DescribeSecret"],
                        "Resource": secret_arn,
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    rotated = _poll_until(
        _current_value,
        lambda v: v != initial_value,
        timeout_s=200.0,
        interval_s=5.0,
        description="secret rotated once the execution role gained secretsmanager permission",
    )
    assert rotated != initial_value, f"expected a changed secret value, got unchanged {rotated!r}"
    assert rotated.startswith("rotated-"), f"unexpected rotated value: {rotated!r}"


_ROTATION_HANDLER_CODE = """
import json
import os
import uuid
import boto3

_sm = boto3.client("secretsmanager")


def handler(event, context):
    secret_id = event.get("SecretId") or os.environ.get("SECRET_ID")
    new_value = "rotated-" + uuid.uuid4().hex
    _sm.put_secret_value(SecretId=secret_id, SecretString=new_value)
    return {"rotated": True, "secretId": secret_id}
"""


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _zip_code(code_str: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("lambda_function.py", code_str)
    return buf.getvalue()


def _create_lambda_role(ctx, extra_statements: list[dict[str, Any]]) -> tuple[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lambdarole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    if extra_statements:
        policy_name = f"{role_name}-inline"
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": extra_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    basic_exec_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_exec_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_exec_arn))
    return role_name, role_arn


def _create_function(
    ctx, name: str, role_arn: str, code_str: str, env: dict[str, str] | None = None, timeout: int = 30
) -> str:
    lam = ctx.client("lambda")
    kwargs: dict[str, Any] = dict(
        FunctionName=name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="lambda_function.handler",
        Code={"ZipFile": _zip_code(code_str)},
        Timeout=timeout,
        Publish=True,
        Tags={"sim2real-check": CHECK},
    )
    if env:
        kwargs["Environment"] = {"Variables": env}

    deadline = time.monotonic() + 60.0
    resp = None
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(**kwargs)
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_exc = exc
            time.sleep(3.0)
    if resp is None:
        raise AssertionError(f"create_function never succeeded (role propagation?): {last_exc}")

    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name).get("State"),
        lambda s: s == "Active",
        timeout_s=60.0,
        interval_s=2.0,
        description=f"function {name} Active",
    )
    return resp["FunctionArn"]


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
