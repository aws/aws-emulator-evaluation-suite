"""cli-create-log-subscription-filter-lambda-workflow."""
from __future__ import annotations

import json
import subprocess
import time
import io
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cli-create-log-subscription-filter-lambda-workflow"
GROUP = "cli-workflow"
SERVICES = ["cloudwatch", "lambda", "logs"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """`aws logs put-subscription-filter` targeting a Lambda function is verified end-to-end:
    a real log event written to the source log group is delivered to (and processed by) the
    subscribed Lambda function, observed via the processor's own CloudWatch Logs output."""
    from fidelity_tests_runner import require_tools

    require_tools("aws")

    logs = ctx.client("logs")
    lam = ctx.client("lambda")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    src_group = ctx.unique_name("sim2real-behav-srcgroup-")
    logs.create_log_group(logGroupName=src_group, tags={"sim2real:managed": "true"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=src_group))

    role_arn = _create_lambda_role(ctx, with_logs_permission=True)
    processor_name = ctx.unique_name("sim2real-behav-subproc-")
    handler_code = (
        "import base64, gzip, json\n"
        "def handler(event, context):\n"
        "    data = event.get('awslogs', {}).get('data')\n"
        "    if not data:\n"
        "        return {'skipped': True}\n"
        "    payload = json.loads(gzip.decompress(base64.b64decode(data)))\n"
        "    if payload.get('messageType') != 'DATA_MESSAGE':\n"
        "        return {'control': True}\n"
        "    for e in payload.get('logEvents', []):\n"
        "        print('RECEIVED::' + e.get('message', ''))\n"
        "    return {'count': len(payload.get('logEvents', []))}\n"
    )
    processor_arn = _create_function(ctx, processor_name, role_arn, handler_code)

    src_group_arn = logs.describe_log_groups(logGroupNamePrefix=src_group)["logGroups"][0]["arn"]
    lam.add_permission(
        FunctionName=processor_name,
        StatementId="allow-cwlogs-invoke",
        Action="lambda:InvokeFunction",
        Principal="logs.amazonaws.com",
        SourceArn=src_group_arn,
        SourceAccount=account_id,
    )

    filter_name = ctx.unique_name("sim2real-behav-subfilter-")
    _run_aws(
        ctx,
        "logs", "put-subscription-filter",
        "--log-group-name", src_group,
        "--filter-name", filter_name,
        "--filter-pattern", "",
        "--destination-arn", processor_arn,
    )
    ctx.on_cleanup(lambda: logs.delete_subscription_filter(logGroupName=src_group, filterName=filter_name))

    marker = ctx.unique_name("sim2real-subfilter-marker-")
    stream_name = ctx.unique_name("sim2real-behav-stream-")
    logs.create_log_stream(logGroupName=src_group, logStreamName=stream_name)
    logs.put_log_events(
        logGroupName=src_group,
        logStreamName=stream_name,
        logEvents=[{"timestamp": int(time.time() * 1000), "message": f"hello {marker}"}],
    )

    expected = f"RECEIVED::hello {marker}"
    proc_group = f"/aws/lambda/{processor_name}"
    found = _poll_for_log_message(ctx, proc_group, expected, timeout_s=90)
    assert found, f"processor function never logged {expected!r} in {proc_group}"


def _poll_for_log_message(ctx, log_group, needle, timeout_s=90, interval_s=5):
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = logs.filter_log_events(logGroupName=log_group)
            for event in resp.get("events", []):
                if needle in event["message"]:
                    return True
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(interval_s)
    return False


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
        ctx, ["aws", "--output", "json", *args], timeout_s=timeout_s, check=check
    )
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _zip_bytes(handler_code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_code)
    return buf.getvalue()


def _create_lambda_role(ctx, with_logs_permission: bool) -> str:
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    if with_logs_permission:
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        )
    return role_arn


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        attached = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
        for p in attached:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_function(ctx, name, role_arn, handler_code, handler="index.handler", timeout_s=15, env_vars=None):
    lam = ctx.client("lambda")
    kwargs = dict(
        FunctionName=name,
        Runtime="python3.12",
        Role=role_arn,
        Handler=handler,
        Code={"ZipFile": _zip_bytes(handler_code)},
        Timeout=timeout_s,
        Publish=True,
        Tags={"sim2real:managed": "true"},
    )
    if env_vars:
        kwargs["Environment"] = {"Variables": env_vars}
    deadline = time.monotonic() + 60
    last_err = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(**kwargs)
            break
        except lam.exceptions.InvalidParameterValueException as e:
            last_err = e
            time.sleep(3)
    if resp is None:
        raise AssertionError(f"create_function never succeeded (role propagation?): {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_for_active(ctx, name)
    return resp["FunctionArn"]


def _wait_for_active(ctx, name, timeout_s=60):
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg["State"] == "Active":
            return
        if cfg["State"] == "Failed":
            raise AssertionError(f"function entered Failed state: {cfg}")
        time.sleep(2)
    raise AssertionError("function never became Active")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
