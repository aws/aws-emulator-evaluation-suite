"""cli-lambda-role-policy-missing-dynamodb-negative-workflow."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

CHECK = "cli-lambda-role-policy-missing-dynamodb-negative-workflow"
GROUP = "overly-permissive"
SERVICES = ["dynamodb", "events", "lambda"]


@tags("axis:rejection", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A function whose role has only AWSLambdaBasicExecutionRole gets AccessDeniedException from dynamodb:PutItem
    and writes no item, while an identical function whose role allows PutItem from creation writes its item.
    """
    require_tools("aws")

    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-behav-tbl-")
    table = ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}],
    )
    table_arn = table["TableDescription"]["TableArn"]
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    ddb.get_waiter("table_exists").wait(TableName=table_name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    handler_code = (
        "import json, os, boto3\n"
        "from botocore.exceptions import ClientError\n"
        "ddb = boto3.client('dynamodb')\n"
        "TABLE = os.environ['TABLE_NAME']\n"
        "def handler(event, context):\n"
        "    item_id = event.get('id', 'unknown')\n"
        "    try:\n"
        "        ddb.put_item(TableName=TABLE, Item={'id': {'S': item_id}})\n"
        "        return {'status': 'ok'}\n"
        "    except ClientError as e:\n"
        "        return {'status': 'error', 'code': e.response['Error']['Code']}\n"
    )

    # Both roles and functions are created up front (the allowed role with its PutItem policy from
    # creation), so IAM propagation has passed before either is invoked and no policy changes mid-test.
    _, role_arn_denied = _create_lambda_role(ctx)  # no inline dynamodb policy
    _, role_arn_allowed = _create_lambda_role(
        ctx, inline_statements=[{"Effect": "Allow", "Action": ["dynamodb:PutItem"], "Resource": table_arn}]
    )

    fn_denied = ctx.unique_name("sim2real-behav-fn-")
    _create_function(ctx, fn_denied, role_arn_denied, handler_code, env={"TABLE_NAME": table_name})

    fn_allowed = ctx.unique_name("sim2real-behav-fn-")
    _create_function(ctx, fn_allowed, role_arn_allowed, handler_code, env={"TABLE_NAME": table_name})

    # Positive control first: the role's PutItem policy has had the full setup/activation time
    # of BOTH functions to propagate, so a short retry suffices.
    allowed_id = ctx.unique_name("allowed-item-")
    control_payload = _invoke_with_retry(ctx, fn_allowed, {"id": allowed_id}, timeout_s=90.0, interval_s=5.0)
    assert control_payload.get("status") == "ok", f"positive control failed: {control_payload}"
    control_resp = ddb.get_item(TableName=table_name, Key={"id": {"S": allowed_id}})
    assert "Item" in control_resp, "positive control: item should be written once PutItem is granted"

    # Negative: the role without the DynamoDB policy is denied and writes nothing.
    denied_id = ctx.unique_name("denied-item-")
    payload = _invoke_lambda_cli(ctx, fn_denied, {"id": denied_id})
    assert payload.get("status") == "error", f"expected the denied invoke to report an error, got: {payload}"
    assert payload.get("code") == "AccessDeniedException", (
        f"expected code AccessDeniedException for the role lacking dynamodb:PutItem, got: {payload}"
    )
    resp = ddb.get_item(TableName=table_name, Key={"id": {"S": denied_id}})
    assert "Item" not in resp, "item must not be written when the role lacks dynamodb:PutItem"


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


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    proc = _run_shell(
        ctx,
        ["aws", "--output", "json", *args],
        timeout_s=timeout_s,
        check=check,
    )
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _make_zip_bytes(handler_code: str) -> bytes:
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_code)
    return buf.getvalue()


def _create_lambda_role(ctx, inline_statements=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn))
    if inline_statements:
        policy_name = f"{role_name}-inline"
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": inline_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_name, role_arn


def _create_function(ctx, name, role_arn, handler_code, env=None, timeout=30):
    lam = ctx.client("lambda")
    zip_bytes = _make_zip_bytes(handler_code)
    kwargs = dict(
        FunctionName=name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="lambda_function.handler",
        Code={"ZipFile": zip_bytes},
        Timeout=timeout,
        Publish=True,
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    if env:
        kwargs["Environment"] = {"Variables": env}
    last_err = None
    deadline = time.monotonic() + 60
    fn_arn = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(**kwargs)
            fn_arn = resp["FunctionArn"]
            break
        except ClientError as e:
            last_err = e
            code = e.response["Error"]["Code"]
            if code == "InvalidParameterValueException":
                time.sleep(3)
                continue
            raise
    if fn_arn is None:
        raise AssertionError(f"create_function never succeeded (role propagation?): {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return fn_arn


def _invoke_lambda_cli(ctx, function_name, payload):
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        out_path = f.name
    try:
        _run_shell(
            ctx,
            [
                "aws",
                "lambda",
                "invoke",
                "--function-name",
                function_name,
                "--payload",
                json.dumps(payload),
                "--cli-binary-format",
                "raw-in-base64-out",
                out_path,
            ],
        )
        with open(out_path) as f:
            return json.load(f)
    finally:
        os.unlink(out_path)


def _invoke_with_retry(ctx, function_name, payload, timeout_s=60.0, interval_s=5.0):
    """IAM policy changes are eventually consistent; retry the invoke until it reflects the
    newly-granted permission or the bound elapses."""
    deadline = time.monotonic() + timeout_s
    result = {}
    while time.monotonic() < deadline:
        result = _invoke_lambda_cli(ctx, function_name, payload)
        if result.get("status") == "ok":
            return result
        time.sleep(interval_s)
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
