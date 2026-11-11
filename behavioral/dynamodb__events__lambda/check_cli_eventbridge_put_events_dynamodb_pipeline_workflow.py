"""cli-eventbridge-put-events-dynamodb-pipeline-workflow."""
from __future__ import annotations

import json
import subprocess
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

CHECK = "cli-eventbridge-put-events-dynamodb-pipeline-workflow"
GROUP = "cli-workflow"
SERVICES = ["dynamodb", "events", "lambda"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A put-events entry sent with the AWS CLI matches a rule whose Lambda target writes the event's id and value
    to DynamoDB, and GetItem then returns that item with the sent value.
    """
    require_tools("aws")

    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-behav-tbl-")
    table = ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    table_arn = table["TableDescription"]["TableArn"]
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    ddb.get_waiter("table_exists").wait(TableName=table_name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    inline_statements = [
        {"Effect": "Allow", "Action": ["dynamodb:PutItem"], "Resource": table_arn}
    ]
    role_name, role_arn = _create_lambda_role(ctx, inline_statements=inline_statements)

    fn_name = ctx.unique_name("sim2real-behav-fn-")
    handler_code = (
        "import json, os, boto3\n"
        "ddb = boto3.client('dynamodb')\n"
        "TABLE = os.environ['TABLE_NAME']\n"
        "def handler(event, context):\n"
        "    detail = event.get('detail', {})\n"
        "    ddb.put_item(TableName=TABLE, Item={'id': {'S': detail['id']}, 'value': {'S': detail['value']}})\n"
        "    return {'ok': True}\n"
    )
    fn_arn = _create_function(ctx, fn_name, role_arn, handler_code, env={"TABLE_NAME": table_name})

    rule_name = ctx.unique_name("sim2real-behav-rule-")
    source_val = ctx.unique_name("sim2real.pipeline.")
    _run_aws(
        ctx,
        "events",
        "put-rule",
        "--name",
        rule_name,
        "--event-pattern",
        json.dumps({"source": [source_val]}),
        "--tags",
        f"Key=sim2real,Value={CHECK}",
    )
    ctx.on_cleanup(lambda: _run_aws(ctx, "events", "delete-rule", "--name", rule_name))

    account_id = _account_id(ctx)
    rule_arn = f"arn:aws:events:{ctx.region}:{account_id}:rule/{rule_name}"

    _run_aws(
        ctx,
        "lambda",
        "add-permission",
        "--function-name",
        fn_name,
        "--statement-id",
        "AllowEventBridgeInvoke",
        "--action",
        "lambda:InvokeFunction",
        "--principal",
        "events.amazonaws.com",
        "--source-arn",
        rule_arn,
    )

    _run_aws(
        ctx,
        "events",
        "put-targets",
        "--rule",
        rule_name,
        "--targets",
        json.dumps([{"Id": "1", "Arn": fn_arn}]),
    )
    ctx.on_cleanup(
        lambda: _run_aws(ctx, "events", "remove-targets", "--rule", rule_name, "--ids", "1")
    )

    item_id = ctx.unique_name("item-")
    value = "pipeline-value-42"
    entries = [
        {
            "Source": source_val,
            "DetailType": "sim2real-pipeline",
            "Detail": json.dumps({"id": item_id, "value": value}),
        }
    ]
    # A new rule, target or role policy may not match or deliver at once (PutRule: allow a short period
    # for changes to take effect), so the same entry is sent again until the item appears or 150 s pass.
    # Each send gets 15 s to be delivered and written before the next one.
    item = None
    deadline = time.monotonic() + min(150.0, ctx.time_left() or 150.0)
    while item is None and time.monotonic() < deadline:
        _run_aws(ctx, "events", "put-events", "--entries", json.dumps(entries))
        item = _poll_for_item(
            ctx, table_name, item_id, timeout_s=min(15.0, max(0.0, deadline - time.monotonic())), interval_s=2.0
        )
    assert item is not None, f"expected item {item_id} to be written by Lambda via EventBridge pipeline"
    assert item["value"]["S"] == value, f"expected item value {value!r}, got {item['value']['S']!r}"


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


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


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
        Tags=[{"Key": "sim2real", "Value": role_name}],
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
        Tags={"sim2real": name},
    )
    if env:
        kwargs["Environment"] = {"Variables": env}
    last_err = None
    deadline = time.monotonic() + 60
    fn_arn = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
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


def _poll_for_item(ctx, table_name, item_id, timeout_s=90.0, interval_s=5.0):
    ddb = ctx.client("dynamodb")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = ddb.get_item(TableName=table_name, Key={"id": {"S": item_id}})
        if "Item" in resp:
            return resp["Item"]
        time.sleep(interval_s)
    return None


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
