"""lambda-sdk-putevents-denied-without-permission."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-sdk-putevents-denied-without-permission"
GROUP = "permission-boundary"
SERVICES = ["events", "lambda", "s3", "stepfunctions"]

_HANDLER_SRC = """
import json, os, boto3
from botocore.exceptions import ClientError

def handler(event, context):
    eb = boto3.client('events')
    try:
        resp = eb.put_events(Entries=[{
            'Source': 'sim2real.custom',
            'DetailType': event.get('detail_type', 'sim2real-test-event'),
            'Detail': json.dumps(event.get('detail', {})),
            'EventBusName': os.environ.get('BUS_NAME', 'default'),
        }])
        return {'ok': True, 'EventId': resp['Entries'][0].get('EventId')}
    except ClientError as e:
        return {'ok': False, 'code': e.response['Error']['Code'], 'message': e.response['Error'].get('Message')}
"""


@tags("axis:negative-delivery", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda whose role lacks events:PutEvents gets AccessDeniedException with its exact message
    and the event never reaches the rule's queue; once granted, the identical call delivers it."""
    detail_type = "sim2real-denied-test-event"
    queue_url, queue_arn = _create_queue_target(ctx)
    _put_rule_with_sqs_target(
        ctx, {"source": ["sim2real.custom"], "detail-type": [detail_type]}, queue_arn, queue_url
    )

    lambda_role_name, lambda_role_arn = _create_lambda_role(ctx)  # no events permission at all
    fn_name, _ = _create_lambda(ctx, lambda_role_arn, _HANDLER_SRC)

    denied_marker = ctx.unique_name("sim2real-denied-marker-")
    denied = _invoke_lambda(ctx, fn_name, {"detail_type": detail_type, "detail": {"marker": denied_marker}})
    assert denied["ok"] is False, f"expected put_events to be denied without permission, got: {denied}"
    assert denied["code"] == "AccessDeniedException", (
        f"expected AccessDeniedException, got code={denied.get('code')!r} (full={denied!r})"
    )
    expected = (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{lambda_role_name}/{fn_name} is not authorized "
        f"to perform: events:PutEvents on resource: arn:aws:events:{ctx.region}:{ctx.account}:"
        "event-bus/default because no identity-based policy allows the events:PutEvents action"
    )
    assert denied["message"] == expected, f"expected {expected!r}, got {denied['message']!r}"

    # Effect absent: no message for the denied marker shows up within a generous window.
    leaked = _wait_for_messages(ctx, queue_url, expected_count=1, timeout_s=15)
    matching_denied = [m for m in leaked if m["body"].get("detail", {}).get("marker") == denied_marker]
    assert matching_denied == [], "event was delivered despite missing events:PutEvents permission"

    # Positive control: grant the missing permission and retry the identical call.
    iam = ctx.client("iam")
    policy_name = "grant-put-events"
    iam.put_role_policy(
        RoleName=lambda_role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "events:PutEvents", "Resource": "*"}],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=lambda_role_name, PolicyName=policy_name))

    allowed_marker = ctx.unique_name("sim2real-allowed-marker-")
    granted = _poll_until(
        lambda: _invoke_lambda(
            ctx, fn_name, {"detail_type": detail_type, "detail": {"marker": allowed_marker}}
        ),
        lambda r: r.get("ok") is True,
        timeout_s=45,
        interval_s=3,
    )
    assert granted["ok"] is True, f"expected put_events to succeed after granting permission, got: {granted}"

    delivered = _wait_for_messages(ctx, queue_url, expected_count=1, timeout_s=60)
    matching_allowed = [m for m in delivered if m["body"].get("detail", {}).get("marker") == allowed_marker]
    assert len(matching_allowed) == 1, (
        f"expected exactly 1 delivered message for marker {allowed_marker!r}, got {len(matching_allowed)}: {delivered}"
    )


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _mgmt_tags() -> dict[str, str]:
    return {"sim2real:managed": "true", "sim2real:check": CHECK}


def _zip_code(handler_src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_src)
    return buf.getvalue()


def _create_lambda_role(ctx, inline_policies: dict[str, Any] | None = None) -> tuple[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": k, "Value": v} for k, v in _mgmt_tags().items()],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy))
    for pname, doc in (inline_policies or {}).items():
        iam.put_role_policy(RoleName=role_name, PolicyName=pname, PolicyDocument=json.dumps(doc))
        ctx.on_cleanup(lambda n=pname: iam.delete_role_policy(RoleName=role_name, PolicyName=n))
    return role_name, role_arn


def _create_lambda(ctx, role_arn: str, handler_src: str, env: dict[str, str] | None = None, timeout: int = 30):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-fn-")
    code = _zip_code(handler_src)
    resp = None
    last_err = None
    for _ in range(12):
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": code},
                Timeout=timeout,
                Environment={"Variables": env or {}},
                Tags=_mgmt_tags(),
            )
            break
        except lam.exceptions.InvalidParameterValueException as e:
            last_err = e
            time.sleep(3)
    if resp is None:
        raise last_err
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda c: c["State"] in ("Active", "Failed"),
        timeout_s=60,
        interval_s=2,
    )
    return name, resp["FunctionArn"]


def _invoke_lambda(ctx, name: str, payload: dict[str, Any]) -> dict[str, Any]:
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=name, Payload=json.dumps(payload).encode("utf-8"), InvocationType="RequestResponse"
    )
    body = json.loads(resp["Payload"].read())
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invocation raised: {body}")
    return body


def _create_queue_target(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-q-"), tags=_mgmt_tags())["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _put_rule_with_sqs_target(ctx, event_pattern: dict[str, Any], queue_arn: str, queue_url: str) -> str:
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    rule_name = ctx.unique_name("sim2real-rule-")
    events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(event_pattern),
        State="ENABLED",
        Tags=[{"Key": k, "Value": v} for k, v in _mgmt_tags().items()],
    )
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    rule_arn = events.describe_rule(Name=rule_name)["Arn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})
    events.put_targets(Rule=rule_name, Targets=[{"Id": "target1", "Arn": queue_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["target1"]))
    return rule_name


def _wait_for_messages(ctx, queue_url: str, expected_count: int = 1, timeout_s: float = 60.0):
    sqs = ctx.client("sqs")
    out: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while len(out) < expected_count and time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                body = msg["Body"]
            out.append({"body": body, "message_id": msg["MessageId"]})
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return out


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
