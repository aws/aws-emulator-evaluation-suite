"""cli-lambda-update-env-vars-dynamodb-table-name."""
from __future__ import annotations

import io
import json
import os
import subprocess
import tempfile
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cli-lambda-update-env-vars-dynamodb-table-name"
GROUP = "cli-roundtrip"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """CLI: update a Lambda's TABLE_NAME env var to point at a different DynamoDB table and
    confirm subsequent writes land in the newly-targeted table, not the old one."""
    from fidelity_tests_runner import require_tools

    require_tools("aws")

    table_a = ctx.unique_name("sim2real-behav-tbla-")
    table_b = ctx.unique_name("sim2real-behav-tblb-")
    for t in (table_a, table_b):
        _run_aws(
            ctx, "dynamodb", "create-table",
            "--table-name", t,
            "--attribute-definitions", "AttributeName=id,AttributeType=S",
            "--key-schema", "AttributeName=id,KeyType=HASH",
            "--billing-mode", "PAY_PER_REQUEST",
            "--tags", f"Key=sim2real-check,Value={CHECK}",
        )
        ctx.on_cleanup(lambda t=t: _run_aws(ctx, "dynamodb", "delete-table", "--table-name", t, check=False))
    _wait_table_active(ctx, table_a)
    _wait_table_active(ctx, table_b)

    role_arn, role_name = _create_lambda_role(
        ctx,
        [
            "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
            "arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess",
        ],
    )

    func_name = ctx.unique_name("sim2real-behav-fn-")
    code = (
        "import os\n"
        "import boto3\n\n"
        "def handler(event, context):\n"
        "    table_name = os.environ['TABLE_NAME']\n"
        "    ddb = boto3.client('dynamodb')\n"
        "    ddb.put_item(TableName=table_name, Item={'id': {'S': event['id']}, 'value': {'S': 'written'}})\n"
        "    return {'table': table_name}\n"
    )
    _create_lambda_function_cli(ctx, func_name, role_arn, _lambda_zip_bytes(code), env={"TABLE_NAME": table_a})
    ctx.on_cleanup(lambda: _run_aws(ctx, "lambda", "delete-function", "--function-name", func_name, check=False))
    _wait_lambda_active(ctx, func_name)

    _invoke(ctx, func_name, {"id": "row-a"})
    ddb = ctx.client("dynamodb")
    resp_a = ddb.get_item(TableName=table_a, Key={"id": {"S": "row-a"}})
    assert "Item" in resp_a, f"expected row-a in {table_a} (TABLE_NAME target) after invoke, got {resp_a}"
    resp_a_wrong = ddb.get_item(TableName=table_b, Key={"id": {"S": "row-a"}})
    assert "Item" not in resp_a_wrong, f"row-a leaked into {table_b} before TABLE_NAME was ever pointed at it: {resp_a_wrong}"

    _run_aws(
        ctx, "lambda", "update-function-configuration",
        "--function-name", func_name,
        "--environment", json.dumps({"Variables": {"TABLE_NAME": table_b}}),
    )
    _wait_env_updated(ctx, func_name, table_b)

    _invoke(ctx, func_name, {"id": "row-b"})
    resp_b = ddb.get_item(TableName=table_b, Key={"id": {"S": "row-b"}})
    assert "Item" in resp_b, f"expected row-b in {table_b} (new TABLE_NAME target) after invoke, got {resp_b}"
    resp_b_wrong = ddb.get_item(TableName=table_a, Key={"id": {"S": "row-b"}})
    assert "Item" not in resp_b_wrong, f"row-b landed in old table {table_a} instead of the updated TABLE_NAME target: {resp_b_wrong}"


def _invoke(ctx, func_name, payload):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as pf:
        json.dump(payload, pf)
        payload_path = pf.name
    outfile = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    outfile.close()
    try:
        _run_aws(
            ctx, "lambda", "invoke",
            "--function-name", func_name,
            "--payload", f"file://{payload_path}",
            "--cli-binary-format", "raw-in-base64-out",
            outfile.name,
        )
        with open(outfile.name) as f:
            return json.load(f)
    finally:
        os.unlink(payload_path)
        os.unlink(outfile.name)


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command, shell=isinstance(command, str), env=env,
        capture_output=True, text=True, timeout=timeout_s, cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


def _run_aws(ctx, *args, timeout_s=30.0, check=True):
    proc = _run_shell(ctx, ["aws", "--output", "json", *args], timeout_s=timeout_s, check=check)
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _lambda_zip_bytes(handler_code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_code)
    return buf.getvalue()


def _create_lambda_role(ctx, policy_arns):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]

    def _cleanup():
        try:
            for p in iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    for arn in policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)
    return role["Arn"], role_name


def _create_lambda_function_cli(ctx, name, role_arn, zip_bytes, handler="lambda_function.handler", env=None, timeout_s=120.0):
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
        f.write(zip_bytes)
        zip_path = f.name
    try:
        args = [
            "lambda", "create-function", "--function-name", name, "--runtime", "python3.12",
            "--role", role_arn, "--handler", handler, "--zip-file", f"fileb://{zip_path}", "--timeout", "30",
            "--tags", f"sim2real-check={CHECK}",
        ]
        if env:
            args += ["--environment", json.dumps({"Variables": env})]
        deadline = time.monotonic() + timeout_s
        last_err = ""
        while time.monotonic() < deadline:
            proc = _run_shell(ctx, ["aws", "--output", "json", *args], timeout_s=30.0, check=False)
            if proc.returncode == 0:
                return
            last_err = proc.stderr
            if "InvalidParameterValueException" in proc.stderr or "cannot be assumed" in proc.stderr:
                time.sleep(3)
                continue
            raise AssertionError(f"create-function failed: {proc.stderr[-500:]}")
        raise AssertionError(f"create-function never succeeded (role propagation timeout): {last_err[-500:]}")
    finally:
        os.unlink(zip_path)


def _wait_lambda_active(ctx, name, timeout_s=90.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = _run_aws(ctx, "lambda", "get-function-configuration", "--function-name", name)
        if cfg.get("State") == "Active":
            return cfg
        time.sleep(2)
    raise AssertionError(f"Lambda {name} never became Active within {timeout_s}s")


def _wait_env_updated(ctx, name, expected_table, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = _run_aws(ctx, "lambda", "get-function-configuration", "--function-name", name)
        env_vars = cfg.get("Environment", {}).get("Variables", {})
        if cfg.get("LastUpdateStatus") == "Successful" and env_vars.get("TABLE_NAME") == expected_table:
            return cfg
        time.sleep(2)
    raise AssertionError(f"Lambda {name} env var update to {expected_table} never completed within {timeout_s}s")


def _wait_table_active(ctx, table_name, timeout_s=90.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = _run_aws(ctx, "dynamodb", "describe-table", "--table-name", table_name)
        if desc["Table"]["TableStatus"] == "ACTIVE":
            return
        time.sleep(2)
    raise AssertionError(f"table {table_name} never became ACTIVE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
