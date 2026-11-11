"""e2e-sqs-trigger."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "e2e-sqs-trigger"
GROUP = 'e2e_workflows'
SERVICES = ['lambda']


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


def _cleanup_fn(ctx, lam, name):
    try:
        lam.delete_function_url_config(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        lam.delete_function(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_active(lam, fn, timeout_s=60):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last["State"] == "Failed":
            raise AssertionError(f"Function {fn} entered Failed: {last.get('StateReason')}")
        if last["State"] == "Active":
            return
        time.sleep(1.0)
    raise AssertionError(f"{fn} Active not met within {timeout_s}s. Last: {last!r}")


def _wait_esm_active(lam, uuid_, timeout_s=60):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_event_source_mapping(UUID=uuid_)
        if last["State"] == "Enabled":
            return
        time.sleep(1.0)
    raise AssertionError(f"ESM {uuid_} Enabled not met within {timeout_s}s. Last: {last!r}")


def _deploy_function(ctx, lam, code, *, name=None, handler="index.handler",
                     runtime="python3.12", memory=128, timeout=30, environment=None,
                     layers=None, ephemeral_storage=None, role=None):
    name = name or ctx.unique_name("sim2real-behav-fn-")
    kwargs = {
        "FunctionName": name,
        "Runtime": runtime,
        "Handler": handler,
        "Role": role,
        "Code": {"ZipFile": _make_zip(code)},
        "MemorySize": memory,
        "Timeout": timeout,
    }
    if environment:
        kwargs["Environment"] = {"Variables": environment}
    if layers:
        kwargs["Layers"] = layers
    if ephemeral_storage:
        kwargs["EphemeralStorage"] = {"Size": ephemeral_storage}
    _create_with_role_retry(lambda: lam.create_function(**kwargs))
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    _wait_active(lam, name)
    return name


def _sqs_exec_role_arn(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-sqs-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Path="/sim2real/",
        Tags=[{"Key": "sim2real:managed", "Value": "true"},
              {"Key": "sim2real:prefix", "Value": "sim2real-behav"}],
    )["Role"]["Arn"]

    def _cleanup_role():
        for pn in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup_role)
    iam.put_role_policy(
        RoleName=role_name, PolicyName="sqs-exec",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow",
                 "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                 "Resource": "arn:aws:logs:*:*:*"},
                {"Effect": "Allow",
                 "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage",
                            "sqs:GetQueueAttributes", "sqs:SendMessage"],
                 "Resource": "*"},
            ],
        }),
    )
    return arn


_ROLE_PROPAGATION_MESSAGES = ("does not have permissions", "cannot be assumed by Lambda")


def _create_with_role_retry(fn, timeout_s=90, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            msg = str(exc)
            retryable = any(s in msg for s in _ROLE_PROPAGATION_MESSAGES)
            if retryable and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _wait_for_invocation_count(logs, log_group, marker, min_count=1, timeout_s=45, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = 0
    while time.monotonic() < deadline:
        try:
            events = logs.filter_log_events(
                logGroupName=log_group, filterPattern=f'"{marker}"'
            )["events"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                events = []
            else:
                raise
        last = len(events)
        if last >= min_count:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"expected >= {min_count} log line(s) matching {marker!r} in {log_group} "
        f"within {timeout_s}s (CloudWatch Logs delivery lag), found {last}"
    )


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """SQS message triggers Lambda function via EventSourceMapping."""
    lam = ctx.client("lambda")
    invocation_marker = "sim2real-trigger-fired"
    # Log a marker so invocation can be proven independently, at the consumer, via
    # CloudWatch Logs -- the queue draining only proves SQS's side of the handoff.
    code = f"""\
def handler(event, context):
    print("{invocation_marker} records=" + str(len(event.get("Records", []))))
    return {{"processed": len(event.get("Records", []))}}
"""
    fn = _deploy_function(ctx, lam, code, role=_sqs_exec_role_arn(ctx))

    # Create SQS queue
    sqs = ctx.client("sqs")
    queue_name = ctx.unique_name("sim2real-behav-q-")
    queue_url = sqs.create_queue(QueueName=queue_name)["QueueUrl"]
    ctx.on_cleanup(lambda u=queue_url: ctx.client("sqs").delete_queue(QueueUrl=u))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    # Create EventSourceMapping (Lambda validates the role's SQS ReceiveMessage
    # permission here; retry through IAM propagation).
    esm = _create_with_role_retry(
        lambda: lam.create_event_source_mapping(
            EventSourceArn=queue_arn,
            FunctionName=fn,
            BatchSize=1,
            Enabled=True,
        )
    )
    ctx.on_cleanup(lambda u=esm["UUID"]: lam.delete_event_source_mapping(UUID=u))
    _wait_esm_active(lam, esm["UUID"])

    # Send a message
    sqs.send_message(QueueUrl=queue_url, MessageBody="trigger-test-sim2real")

    # Wait for Lambda to consume it (queue should drain)
    consumed = False
    left = ctx.time_left()
    deadline = time.monotonic() + (60.0 if left is None else min(60.0, left))
    while True:
        attrs = sqs.get_queue_attributes(
            QueueUrl=queue_url,
            AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
        )["Attributes"]
        visible = int(attrs.get("ApproximateNumberOfMessages", "1"))
        in_flight = int(attrs.get("ApproximateNumberOfMessagesNotVisible", "1"))
        if visible == 0 and in_flight == 0:
            consumed = True
            break
        if time.monotonic() >= deadline:
            break
        time.sleep(2)
    assert consumed, "SQS message was not consumed by Lambda ESM within 60s"

    # The queue draining only proves SQS's side of the handoff -- a broken ESM that
    # deletes messages without ever invoking the function would also drain the queue.
    # Read the consumer independently, via CloudWatch Logs, and require exactly one
    # invocation for the single message sent.
    log_group = f"/aws/lambda/{fn}"
    invocation_count = _wait_for_invocation_count(
        ctx.client("logs"), log_group, invocation_marker
    )
    assert invocation_count == 1, (
        f"expected exactly 1 Lambda invocation for the single SQS message sent, "
        f"found {invocation_count} matching log lines in {log_group}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
