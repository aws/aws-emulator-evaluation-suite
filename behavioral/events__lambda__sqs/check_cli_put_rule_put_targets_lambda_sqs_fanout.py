"""cli-put-rule-put-targets-lambda-sqs-fanout."""
from __future__ import annotations

import io
import json
import os
import subprocess
import tempfile
import time
import zipfile

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-put-rule-put-targets-lambda-sqs-fanout"
GROUP = "cli-workflow"
SERVICES = ["events", "lambda", "sqs"]

_MANAGED_TAGS = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-fanout"}]
_MANAGED_TAGS_DICT = {t["Key"]: t["Value"] for t in _MANAGED_TAGS}

RELAY_HANDLER_CODE = """
import json
import os
import boto3

sqs = boto3.client("sqs")
SINK_QUEUE_URL = os.environ["SINK_QUEUE_URL"]


def handler(event, context):
    sqs.send_message(QueueUrl=SINK_QUEUE_URL, MessageBody=json.dumps(event))
    return {"status": "ok"}
"""

LAMBDA_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A single EventBridge PutTargets call fanning out to both a Lambda function and an SQS
    queue delivers the SAME event to both targets independently."""
    require_tools("aws")

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    rule_name = ctx.unique_name("sim2real-fanout-rule-")
    rule_arn = f"arn:aws:events:{ctx.region}:{account_id}:rule/{rule_name}"

    sink = _create_queue(ctx, "sink")  # relay lambda writes forwarded events here
    direct = _create_queue(ctx, "direct")  # direct EventBridge->SQS target

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridge",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": direct["arn"],
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    ctx.client("sqs").set_queue_attributes(QueueUrl=direct["url"], Attributes={"Policy": json.dumps(policy)})

    role_arn = _create_lambda_role(ctx, [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": sink["arn"]}])
    fn = _create_relay_lambda(ctx, role_arn, sink["url"])

    _run_aws(
        ctx,
        "lambda",
        "add-permission",
        "--function-name",
        fn["name"],
        "--statement-id",
        "sim2real-eb-invoke",
        "--action",
        "lambda:InvokeFunction",
        "--principal",
        "events.amazonaws.com",
        "--source-arn",
        rule_arn,
    )

    detail_type = "sim2real-fanout"
    _run_aws(
        ctx,
        "events",
        "put-rule",
        "--name",
        rule_name,
        "--event-pattern",
        json.dumps({"source": ["sim2real.test"], "detail-type": [detail_type]}),
        "--tags",
        json.dumps(_MANAGED_TAGS),
    )
    ctx.on_cleanup(lambda: _remove_targets_and_delete_rule(ctx, rule_name, ["1", "2"]))

    _run_aws(
        ctx,
        "events",
        "put-targets",
        "--rule",
        rule_name,
        "--targets",
        json.dumps([{"Id": "1", "Arn": fn["arn"]}, {"Id": "2", "Arn": direct["arn"]}]),
    )

    marker = ctx.unique_name("marker-")
    _run_aws(
        ctx,
        "events",
        "put-events",
        "--entries",
        json.dumps(
            [
                {
                    "Source": "sim2real.test",
                    "DetailType": detail_type,
                    "Detail": json.dumps({"marker": marker}),
                }
            ]
        ),
    )

    via_lambda = _drain_queue_for(ctx, sink["url"], lambda body: _detail_marker(body) == marker)
    via_direct = _drain_queue_for(ctx, direct["url"], lambda body: _detail_marker(body) == marker)

    assert via_lambda is not None, "fan-out event never reached the Lambda target"
    assert via_direct is not None, "fan-out event never reached the SQS target"
    assert via_lambda.get("source") == "sim2real.test" and via_lambda.get("detail-type") == detail_type, (
        f"lambda-relayed event envelope diverged from what was published: {via_lambda!r}"
    )
    assert via_direct.get("source") == "sim2real.test" and via_direct.get("detail-type") == detail_type, (
        f"direct-to-SQS event envelope diverged from what was published: {via_direct!r}"
    )


def _detail_marker(body):
    if not isinstance(body, dict):
        return None
    detail = body.get("detail")
    if isinstance(detail, str):
        try:
            detail = json.loads(detail)
        except (json.JSONDecodeError, ValueError):
            return None
    if isinstance(detail, dict):
        return detail.get("marker")
    return None


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
        ctx,
        ["aws", "--output", "json", *args],
        timeout_s=timeout_s,
        check=check,
        env_extra={"AWS_PAGER": ""},
    )
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _create_queue(ctx, name_hint="q"):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name(f"sim2real-{name_hint}-"), tags=_MANAGED_TAGS_DICT
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _create_lambda_role(ctx, extra_policy_statements):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-role-")
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=LAMBDA_TRUST_POLICY, Tags=_MANAGED_TAGS
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn))
    if extra_policy_statements:
        policy_name = f"{role_name}-inline"
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": extra_policy_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _build_zip(handler_code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_code)
    return buf.getvalue()


def _create_relay_lambda(ctx, role_arn, sink_queue_url):
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-relay-")
    zip_bytes = _build_zip(RELAY_HANDLER_CODE)
    resp = None
    last_err = None
    for _ in range(12):
        try:
            resp = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                Environment={"Variables": {"SINK_QUEUE_URL": sink_queue_url}},
                Tags=_MANAGED_TAGS_DICT,
            )
            break
        except lam.exceptions.InvalidParameterValueException as e:
            last_err = e
            time.sleep(3)
    if resp is None:
        raise AssertionError(f"lambda create_function never succeeded: {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    lam.get_waiter("function_active_v2").wait(FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return {"name": fn_name, "arn": resp["FunctionArn"]}


def _remove_targets_and_delete_rule(ctx, rule_name, target_ids):
    events = ctx.client("events")
    try:
        events.remove_targets(Rule=rule_name, Ids=target_ids)
    except events.exceptions.ResourceNotFoundException:
        pass
    try:
        events.delete_rule(Name=rule_name)
    except events.exceptions.ResourceNotFoundException:
        pass


def _drain_queue_for(ctx, queue_url, match_fn, timeout_s=60.0, interval_s=2.0):
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            try:
                parsed = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                parsed = msg["Body"]
            if match_fn(parsed):
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
                return parsed
        time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
