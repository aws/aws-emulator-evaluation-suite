"""cli-lambda-esm-dynamodb-stream-workflow."""
from __future__ import annotations

import json
import subprocess
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

CHECK = "cli-lambda-esm-dynamodb-stream-workflow"
GROUP = "cli-workflow"
SERVICES = ["dynamodb", "events", "lambda"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """CLI workflow: create a DynamoDB table with streams enabled and a Lambda event source
    mapping on that stream; a PutItem is observed as an invocation via CloudWatch Logs."""
    require_tools("aws")

    table_name = ctx.unique_name("sim2real-behav-tbl-")
    _run_aws(
        ctx,
        "dynamodb",
        "create-table",
        "--table-name",
        table_name,
        "--attribute-definitions",
        "AttributeName=id,AttributeType=S",
        "--key-schema",
        "AttributeName=id,KeyType=HASH",
        "--billing-mode",
        "PAY_PER_REQUEST",
        "--stream-specification",
        "StreamEnabled=true,StreamViewType=NEW_IMAGE",
    )
    ctx.on_cleanup(lambda: _run_aws(ctx, "dynamodb", "delete-table", "--table-name", table_name, check=False))

    ddb = ctx.client("dynamodb")
    ddb.get_waiter("table_exists").wait(TableName=table_name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    desc = ddb.describe_table(TableName=table_name)
    stream_arn = desc["Table"]["LatestStreamArn"]
    assert stream_arn, "expected LatestStreamArn on a stream-enabled table"

    inline_statements = [
        {
            "Effect": "Allow",
            "Action": ["dynamodb:GetRecords", "dynamodb:GetShardIterator", "dynamodb:DescribeStream"],
            "Resource": stream_arn,
        },
        {"Effect": "Allow", "Action": ["dynamodb:ListStreams"], "Resource": "*"},
    ]
    role_name, role_arn = _create_lambda_role(ctx, inline_statements=inline_statements)

    fn_name = ctx.unique_name("sim2real-behav-fn-")
    handler_code = (
        "import json\n"
        "def handler(event, context):\n"
        "    for record in event.get('Records', []):\n"
        "        new_image = record.get('dynamodb', {}).get('NewImage', {})\n"
        "        print('MARKER_STREAM_RECORD:' + json.dumps(new_image))\n"
        "    return {'count': len(event.get('Records', []))}\n"
    )
    _create_function(ctx, fn_name, role_arn, handler_code)

    esm = _run_aws(
        ctx,
        "lambda",
        "create-event-source-mapping",
        "--function-name",
        fn_name,
        "--event-source-arn",
        stream_arn,
        "--starting-position",
        "TRIM_HORIZON",
        "--batch-size",
        "1",
    )
    mapping_uuid = esm["UUID"]
    ctx.on_cleanup(
        lambda: _run_aws(ctx, "lambda", "delete-event-source-mapping", "--uuid", mapping_uuid, check=False)
    )
    _wait_esm_enabled(ctx, mapping_uuid, timeout_s=90.0, interval_s=5.0)

    token = ctx.unique_name("stream-marker-")
    ddb.put_item(TableName=table_name, Item={"id": {"S": token}, "kind": {"S": "stream-test"}})

    # The ESM reaching "Enabled" does not mean its poller already has usable stream-read
    # permissions: IAM propagation for the inline policy can lag behind the state transition,
    # so the first successful poll (and the log delivery after it) can land well past 90s.
    found = _poll_logs_for_marker(ctx, fn_name, token, timeout_s=150.0, interval_s=5.0)
    assert found, f"expected marker {token} to appear in Lambda logs after a DynamoDB stream event"


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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
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


def _wait_esm_enabled(ctx, mapping_uuid, timeout_s=90.0, interval_s=5.0):
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        resp = lam.get_event_source_mapping(UUID=mapping_uuid)
        state = resp["State"]
        if state == "Enabled":
            return
        time.sleep(interval_s)
    raise AssertionError(f"event source mapping never became Enabled: last state {state}")


def _poll_logs_for_marker(ctx, function_name, marker, timeout_s=90.0, interval_s=5.0):
    logs = ctx.client("logs")
    log_group = f"/aws/lambda/{function_name}"
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = logs.filter_log_events(logGroupName=log_group)
        except logs.exceptions.ResourceNotFoundException:
            time.sleep(interval_s)
            continue
        for event in resp.get("events", []):
            if marker in event.get("message", ""):
                return True
        time.sleep(interval_s)
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
