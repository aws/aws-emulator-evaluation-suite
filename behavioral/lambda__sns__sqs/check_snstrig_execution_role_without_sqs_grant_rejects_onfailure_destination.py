"""snstrig-execution-role-without-sqs-grant-rejects-onfailure-destination."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "snstrig-execution-role-without-sqs-grant-rejects-onfailure-destination"
GROUP = "async-destinations"
SERVICES = ["lambda", "sns", "sqs"]

_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"

_HANDLER_SRC = """
def handler(event, context):
    raise RuntimeError("intentional-failure-for-snstrig-destination-permission-test")
"""

#: IAM propagation lag: PutFunctionEventInvokeConfig checks the execution role's permissions
#: synchronously, so a just-granted inline policy can still be rejected for a short window.
_IAM_PROPAGATION_DEADLINE_S = 60.0
_DELIVERY_DEADLINE_S = 90.0


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _error_code(fn):
    """The Error.Code ``fn`` raises. Raises when the call SUCCEEDS: real AWS rejects it."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """PutFunctionEventInvokeConfig rejects an OnFailure queue the execution role cannot SendMessage to.
    No config is stored; after granting the role sqs:SendMessage the same call succeeds, and an
    SNS-triggered failure delivers a RetriesExhausted record for this probe to the queue."""
    lam = ctx.client("lambda")
    sns = ctx.client("sns")
    iam = ctx.client("iam")

    queue_url, queue_arn = _create_queue(ctx)
    role_arn, role_name = _create_lambda_role(ctx)
    fn_name, fn_arn = _create_function(ctx, role_arn)

    code, message = _error_code(
        lambda: lam.put_function_event_invoke_config(
            FunctionName=fn_name, MaximumRetryAttempts=0,
            DestinationConfig={"OnFailure": {"Destination": queue_arn}},
        )
    )
    assert code == "InvalidParameterValueException", (
        f"expected InvalidParameterValueException for a destination the role cannot send to, "
        f"got {code!r}: {message!r}"
    )
    assert message == f"The function execution role does not have permissions to call SendMessage on {queue_arn}", (
        f"unexpected rejection message: {message!r}"
    )
    no_config_code, _no_config_msg = _error_code(
        lambda: lam.get_function_event_invoke_config(FunctionName=fn_name)
    )
    assert no_config_code == "ResourceNotFoundException", (
        f"the rejected call must leave NO event-invoke config stored, got {no_config_code!r} "
        f"from GetFunctionEventInvokeConfig (expected ResourceNotFoundException)"
    )

    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="onfailure-destination",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="onfailure-destination"))
    cfg = _retry_until_granted(
        lambda: lam.put_function_event_invoke_config(
            FunctionName=fn_name, MaximumRetryAttempts=0,
            DestinationConfig={"OnFailure": {"Destination": queue_arn}},
        )
    )
    assert cfg["DestinationConfig"]["OnFailure"]["Destination"] == queue_arn, (
        f"the repaired call must store the destination, got {cfg['DestinationConfig']!r}"
    )

    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-xsvc-topic-"), Tags=_xsvc_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))
    lam.add_permission(
        FunctionName=fn_name, StatementId="sns-invoke", Action="lambda:InvokeFunction",
        Principal="sns.amazonaws.com", SourceArn=topic_arn,
    )
    sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="lambda", Endpoint=fn_arn, ReturnSubscriptionArn=True)["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))

    marker = ctx.unique_name("sim2real-xsvc-repair-probe-")
    sns.publish(TopicArn=topic_arn, Message=marker)
    record = _wait_for_message(ctx, queue_url, timeout_s=_DELIVERY_DEADLINE_S)
    rc = record.get("requestContext", {})
    assert rc.get("condition") == "RetriesExhausted", (
        f"the now-valid destination must carry a real OnFailure record, got condition "
        f"{rc.get('condition')!r}: {record!r}"
    )
    # Bind the record to THIS probe: the SNS envelope it failed on, and the function that failed.
    payload_message = record.get("requestPayload", {}).get("Records", [{}])[0].get("Sns", {}).get("Message")
    assert payload_message == marker, (
        f"the OnFailure record must carry the probe's own SNS message {marker!r} in "
        f"requestPayload.Records[0].Sns.Message, got {payload_message!r}: {record!r}"
    )
    assert rc.get("functionArn") == f"{fn_arn}:$LATEST", (
        f"the OnFailure record must name the failing function {fn_arn}:$LATEST, got "
        f"{rc.get('functionArn')!r}"
    )



def _retry_until_granted(fn, timeout_s: float = _IAM_PROPAGATION_DEADLINE_S):
    """Retry `fn` while it fails on the exact role-propagation error; return its result."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException" or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-xsvc-q-"), tags=_xsvc_resource_tags()
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_lambda_role(ctx) -> tuple[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-xsvc-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_xsvc_tags_kv()
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    # Logs-only: the role is deliberately NOT given sqs:SendMessage until the repair step.
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="base",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "arn:aws:logs:*:*:*",
            }],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="base"))
    return role_arn, role_name


def _zip_bytes(src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", src)
    return buf.getvalue()


def _create_function(ctx, role_arn: str) -> tuple[str, str]:
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-xsvc-fn-")
    last_err: Exception | None = None
    resp = None
    for _ in range(10):
        try:
            resp = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": _zip_bytes(_HANDLER_SRC)},
                Timeout=15,
                Tags=dict(_xsvc_resource_tags()),
            )
            break
        except ClientError as exc:
            last_err = exc
            if exc.response["Error"]["Code"] == "InvalidParameterValueException":
                time.sleep(2)
                continue
            raise
    if resp is None:
        raise AssertionError(f"could not create function after retries: {last_err}")
    # The function auto-creates /aws/lambda/<name> on first invoke and that group survives the
    # function; registered first so LIFO reaps it after delete_function stops new invocations.
    ctx.on_cleanup(lambda: _reap_log_group(ctx, fn_name))
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    lam.get_waiter("function_active_v2").wait(FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return fn_name, resp["FunctionArn"]


def _reap_log_group(ctx, function_name: str, *, quiet_reads: int = 3, max_rounds: int = 12,
                    interval_s: float = 5.0) -> None:
    """delete_function never removes /aws/lambda/<fn>, and a late log flush can recreate it after
    a delete, so delete until the group has read absent several times running; raise if it keeps
    reappearing."""
    logs = ctx.client("logs")
    group = f"/aws/lambda/{function_name}"
    quiet = 0
    for _ in range(max_rounds):
        found = logs.describe_log_groups(logGroupNamePrefix=group).get("logGroups", [])
        if any(g["logGroupName"] == group for g in found):
            quiet = 0
            try:
                logs.delete_log_group(logGroupName=group)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            quiet += 1
            if quiet >= quiet_reads:
                return
        time.sleep(interval_s)
    raise RuntimeError(f"log group {group} kept reappearing after delete")


def _wait_for_message(ctx, queue_url: str, timeout_s: float) -> dict:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        remaining = max(1, int(deadline - time.monotonic()))
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=min(10, remaining))
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            return json.loads(msg["Body"])
    raise AssertionError(f"no OnFailure record delivered to {queue_url} within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
