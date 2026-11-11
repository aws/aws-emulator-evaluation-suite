"""cli-dynamodb-put-item-then-lambda-scan."""
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

CHECK = "cli-dynamodb-put-item-then-lambda-scan"
GROUP = "cli-roundtrip"
SERVICES = ["apigateway", "dynamodb", "lambda", "logs"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda scan returns the item put into the table; after deletion an independent read shows
    the table and function gone and a further operation on each fails."""
    from fidelity_tests_runner import require_tools

    require_tools("aws")

    table_name = ctx.unique_name("sim2real-behav-tbl-")
    _run_aws(
        ctx, "dynamodb", "create-table",
        "--table-name", table_name,
        "--attribute-definitions", "AttributeName=id,AttributeType=S",
        "--key-schema", "AttributeName=id,KeyType=HASH",
        "--billing-mode", "PAY_PER_REQUEST",
        "--tags", "Key=sim2real:managed,Value=true", "Key=sim2real:prefix,Value=sim2real-behav",
    )
    ctx.on_cleanup(lambda: _run_aws(ctx, "dynamodb", "delete-table", "--table-name", table_name, check=False))
    _wait_table_active(ctx, table_name)

    item_id = ctx.unique_name("item-")
    _run_aws(
        ctx, "dynamodb", "put-item",
        "--table-name", table_name,
        "--item", json.dumps({"id": {"S": item_id}, "value": {"S": "hello-world"}}),
    )

    role_arn, role_name = _create_lambda_role(
        ctx,
        [
            "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
            "arn:aws:iam::aws:policy/AmazonDynamoDBReadOnlyAccess",
        ],
    )

    func_name = ctx.unique_name("sim2real-behav-fn-")
    code = (
        "import os\n"
        "import boto3\n\n"
        "def handler(event, context):\n"
        "    table_name = os.environ['TABLE_NAME']\n"
        "    ddb = boto3.client('dynamodb')\n"
        "    resp = ddb.scan(TableName=table_name)\n"
        "    return {'count': len(resp.get('Items', [])), 'items': resp.get('Items', [])}\n"
    )
    _create_lambda_function_cli(
        ctx, func_name, role_arn, _lambda_zip_bytes(code), env={"TABLE_NAME": table_name},
        tags="sim2real:managed=true,sim2real:prefix=sim2real-behav",
    )
    ctx.on_cleanup(lambda: _run_aws(ctx, "lambda", "delete-function", "--function-name", func_name, check=False))
    _wait_lambda_active(ctx, func_name)

    outfile = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    outfile.close()
    _run_aws(ctx, "lambda", "invoke", "--function-name", func_name, outfile.name)
    with open(outfile.name) as f:
        invoke_result = json.load(f)
    os.unlink(outfile.name)

    matches = [it for it in invoke_result["items"] if it.get("id", {}).get("S") == item_id]
    assert len(matches) == 1, f"expected exactly 1 matching item, got {matches}"
    assert matches[0]["value"]["S"] == "hello-world", (
        f"expected value 'hello-world' for item {item_id}, got {matches[0]['value']}"
    )

    _run_aws(ctx, "lambda", "delete-function", "--function-name", func_name)
    lambda_gone = _run_shell(
        ctx, ["aws", "--output", "json", "lambda", "get-function", "--function-name", func_name],
        check=False,
    )
    assert lambda_gone.returncode != 0 and "ResourceNotFoundException" in lambda_gone.stderr, (
        f"expected ResourceNotFoundException reading deleted function {func_name}, "
        f"got rc={lambda_gone.returncode} stderr={lambda_gone.stderr[-300:]}"
    )
    lambda_invoke_dead = _run_shell(
        ctx, ["aws", "--output", "json", "lambda", "invoke", "--function-name", func_name, "/dev/null"],
        check=False,
    )
    assert lambda_invoke_dead.returncode != 0 and "ResourceNotFoundException" in lambda_invoke_dead.stderr, (
        f"expected invoke on deleted function {func_name} to fail with ResourceNotFoundException, "
        f"got rc={lambda_invoke_dead.returncode} stderr={lambda_invoke_dead.stderr[-300:]}"
    )

    _run_aws(ctx, "dynamodb", "delete-table", "--table-name", table_name)
    _wait_table_gone(ctx, table_name)
    put_on_dead_table = _run_shell(
        ctx,
        [
            "aws", "--output", "json", "dynamodb", "put-item",
            "--table-name", table_name,
            "--item", json.dumps({"id": {"S": ctx.unique_name("item-")}, "value": {"S": "post-delete"}}),
        ],
        check=False,
    )
    assert put_on_dead_table.returncode != 0 and "ResourceNotFoundException" in put_on_dead_table.stderr, (
        f"expected put-item on deleted table {table_name} to fail with ResourceNotFoundException, "
        f"got rc={put_on_dead_table.returncode} stderr={put_on_dead_table.stderr[-300:]}"
    )



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
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
        ],
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


def _create_lambda_function_cli(
    ctx, name, role_arn, zip_bytes, handler="lambda_function.handler", env=None, timeout_s=120.0, tags=None,
):
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
        f.write(zip_bytes)
        zip_path = f.name
    try:
        args = [
            "lambda", "create-function", "--function-name", name, "--runtime", "python3.12",
            "--role", role_arn, "--handler", handler, "--zip-file", f"fileb://{zip_path}", "--timeout", "30",
        ]
        if env:
            args += ["--environment", json.dumps({"Variables": env})]
        if tags:
            args += ["--tags", tags]
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


def _wait_table_active(ctx, table_name, timeout_s=90.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = _run_aws(ctx, "dynamodb", "describe-table", "--table-name", table_name)
        if desc["Table"]["TableStatus"] == "ACTIVE":
            return
        time.sleep(2)
    raise AssertionError(f"table {table_name} never became ACTIVE within {timeout_s}s")


def _wait_table_gone(ctx, table_name, timeout_s=120.0):
    """DynamoDB delete-table is async: describe-table keeps succeeding (status DELETING) for a
    while after the delete call returns, so absence must be polled, not asserted immediately."""
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        proc = _run_shell(
            ctx, ["aws", "--output", "json", "dynamodb", "describe-table", "--table-name", table_name],
            check=False,
        )
        if proc.returncode != 0:
            if "ResourceNotFoundException" in proc.stderr:
                return
            raise AssertionError(f"unexpected error waiting for table {table_name} to disappear: {proc.stderr[-300:]}")
        if proc.stdout.strip():
            last_status = json.loads(proc.stdout)["Table"]["TableStatus"]
        time.sleep(3)
    raise AssertionError(f"table {table_name} still describable after {timeout_s}s (last status: {last_status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
