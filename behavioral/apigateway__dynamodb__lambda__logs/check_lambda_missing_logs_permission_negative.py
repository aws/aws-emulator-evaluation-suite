"""lambda-missing-logs-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags

CHECK = "lambda-missing-logs-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]

_BASIC_EXEC_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"

_HANDLER_CODE = """
def handler(event, context):
    return {"ok": True}
"""


@tags("axis:negative-delivery", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """Execution role lacking logs:CreateLogGroup/PutLogEvents -> invocation succeeds but
    no log group/events are ever written; a properly-permissioned function (in the same
    file) does get its logs delivered."""
    # --- broken: execution role with NO CloudWatch Logs permissions at all ---
    bare_role_arn = _create_lambda_role(ctx)  # trust policy only, no policies attached
    bare_name, _bare_arn = _create_function(ctx, bare_role_arn, _HANDLER_CODE)
    bare_log_group = f"/aws/lambda/{bare_name}"
    _register_log_group_cleanup(ctx, bare_log_group)

    lam = ctx.client("lambda")
    bare_resp = lam.invoke(FunctionName=bare_name, Payload=json.dumps({}).encode("utf-8"))
    assert bare_resp["StatusCode"] == 200, f"expected StatusCode 200, got {bare_resp['StatusCode']!r}"
    assert "FunctionError" not in bare_resp, (
        f"invocation must succeed even without logging permissions, got {bare_resp.get('FunctionError')!r}"
    )
    bare_payload = json.loads(bare_resp["Payload"].read())
    assert bare_payload == {"ok": True}, f"expected {{'ok': True}}, got {bare_payload!r}"

    # --- positive control: same handler, role WITH the managed logs policy ---
    good_role_arn = _create_lambda_role(ctx, managed_policy_arns=[_BASIC_EXEC_POLICY_ARN])
    good_name, _good_arn = _create_function(ctx, good_role_arn, _HANDLER_CODE)
    good_log_group = f"/aws/lambda/{good_name}"
    _register_log_group_cleanup(ctx, good_log_group)

    good_resp = lam.invoke(FunctionName=good_name, Payload=json.dumps({}).encode("utf-8"))
    assert good_resp["StatusCode"] == 200, f"expected StatusCode 200, got {good_resp['StatusCode']!r}"

    # give the control every chance to appear before checking the broken group's absence
    _wait_for_log_group(ctx, good_log_group, timeout_s=90.0)

    logs = ctx.client("logs")
    broken_groups = logs.describe_log_groups(logGroupNamePrefix=bare_log_group).get(
        "logGroups", []
    )
    assert broken_groups == [], (
        "log group appeared for a function whose execution role has no CloudWatch "
        "Logs permissions"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_lambda_role(ctx, extra_statements=None, managed_policy_arns=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    for policy_arn in managed_policy_arns or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        ctx.on_cleanup(
            lambda p=policy_arn: iam.detach_role_policy(RoleName=role_name, PolicyArn=p)
        )
    if extra_statements:
        policy_name = ctx.unique_name("sim2real-behav-policy-")
        doc = {"Version": "2012-10-17", "Statement": extra_statements}
        iam.put_role_policy(
            RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(doc)
        )
        ctx.on_cleanup(
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        )
    return role_arn


def _create_function(
    ctx,
    role_arn,
    code,
    *,
    timeout=15,
    memory=128,
    env=None,
    logging_config=None,
    runtime="python3.12",
    handler="lambda_function.handler",
):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-fn-")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("lambda_function.py", code)
    kwargs = dict(
        FunctionName=name,
        Runtime=runtime,
        Role=role_arn,
        Handler=handler,
        Code={"ZipFile": buf.getvalue()},
        Timeout=timeout,
        MemorySize=memory,
        Publish=True,
        Tags={"sim2real": CHECK},
    )
    if env:
        kwargs["Environment"] = {"Variables": env}
    if logging_config:
        kwargs["LoggingConfig"] = logging_config
    last_err = None
    resp = None
    for _ in range(10):
        try:
            resp = lam.create_function(**kwargs)
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(3)
    if resp is None:
        raise last_err
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_active(ctx, name)
    return name, resp["FunctionArn"]


def _wait_active(ctx, name, timeout_s=60.0):
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg["State"] == "Active":
            return
        time.sleep(2)
    raise AssertionError(f"function {name} never became Active")


def _register_log_group_cleanup(ctx, log_group_name):
    logs = ctx.client("logs")

    def _cleanup():
        try:
            logs.delete_log_group(logGroupName=log_group_name)
        except logs.exceptions.ResourceNotFoundException:
            pass

    ctx.on_cleanup(_cleanup)


def _wait_for_log_group(ctx, log_group_name, timeout_s=90.0, interval_s=3.0):
    logs = ctx.client("logs")

    def probe():
        resp = logs.describe_log_groups(logGroupNamePrefix=log_group_name)
        return [g["logGroupName"] for g in resp.get("logGroups", [])]

    return _poll_until(
        probe, lambda names: log_group_name in names, timeout_s=timeout_s, interval_s=interval_s
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
