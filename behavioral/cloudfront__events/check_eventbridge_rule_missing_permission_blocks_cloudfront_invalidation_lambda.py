"""eventbridge-rule-missing-permission-blocks-cloudfront-invalidation-lambda."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "eventbridge-rule-missing-permission-blocks-cloudfront-invalidation-lambda"
GROUP = "overly-permissive"
SERVICES = ["cloudfront", "events"]


@tags("axis:negative-delivery", "cap:c3", "cap:c7", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A matching event invokes the rule's Lambda target whose resource policy grants events.amazonaws.com
    lambda:InvokeFunction for the rule ARN, and never the second target on the same rule without that grant."""
    queue = _create_queue(ctx)
    role_arn = _create_lambda_role(ctx)
    control_fn, control_arn = _create_forwarder_lambda(ctx, role_arn, queue["url"], "control")
    unpermitted_fn, unpermitted_arn = _create_forwarder_lambda(ctx, role_arn, queue["url"], "unpermitted")

    events = ctx.client("events")
    lam = ctx.client("lambda")
    pattern = {"source": ["cfevt.synthetic"], "detail-type": ["InvalidationTrigger"]}
    rule_name = ctx.unique_name("sim2real-cfevt-rule-")
    rule_arn = events.put_rule(Name=rule_name, EventPattern=json.dumps(pattern), State="ENABLED")["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    events.tag_resource(ResourceARN=rule_arn, Tags=[{"Key": "sim2real", "Value": CHECK}])

    # Only the control target gets the resource-based invoke permission.
    sid = ctx.unique_name("sim2real-cfevt-perm-")
    lam.add_permission(
        FunctionName=control_fn,
        StatementId=sid,
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule_arn,
    )
    events.put_targets(
        Rule=rule_name,
        Targets=[{"Id": "t-control", "Arn": control_arn}, {"Id": "t-unpermitted", "Arn": unpermitted_arn}],
    )
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["t-control", "t-unpermitted"]))

    def _fire_event() -> None:
        events.put_events(Entries=[{"Source": "cfevt.synthetic", "DetailType": "InvalidationTrigger", "Detail": "{}"}])

    # A freshly created rule/target pair is not always evaluated by every EventBridge host
    # immediately (documented eventual consistency): the first put_events can be evaluated
    # before propagation finishes and never match anything. Resend on a bounded schedule
    # rather than trust a single attempt or a blind sleep -- harmless to resend since the
    # thing under test is target-level permission enforcement, not event delivery count.
    control_body = None
    other_msgs: list[dict[str, Any]] = []
    deadline = time.monotonic() + 180.0
    _fire_event()
    while time.monotonic() < deadline:
        control_body = _peek_labeled_message(ctx, queue["url"], "control", other_msgs, wait_s=20.0)
        if control_body is not None:
            break
        _fire_event()
    if control_body is None:
        raise AssertionError("control target was never invoked within 180s despite repeated put_events")
    assert control_body["label"] == "control", f"expected the control target's own label, got {control_body!r}"

    leftover = other_msgs + _drain_queue(ctx, queue["url"], max_wait_s=45.0)
    unpermitted_msgs = [m for m in leftover if m.get("label") == "unpermitted"]
    assert unpermitted_msgs == [], f"unpermitted target was invoked despite missing permission: {unpermitted_msgs}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _create_queue(ctx) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-cfevt-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    sqs.tag_queue(QueueUrl=url, Tags={"sim2real": CHECK})
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _peek_labeled_message(
    ctx, queue_url: str, label: str, other_sink: list[dict[str, Any]], wait_s: float = 20.0
) -> dict[str, Any] | None:
    """One bounded receive; returns the labeled body if present, else None (never blocks past wait_s).

    Any message NOT matching ``label`` is appended to ``other_sink`` rather than discarded, so an
    early "unpermitted" delivery is not silently lost while this is still waiting for "control".
    """
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + wait_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=min(10, max(1, int(wait_s)))
        )
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if body.get("label") == label:
                return body
            other_sink.append(body)
    return None


def _drain_queue(ctx, queue_url: str, max_wait_s: float = 30.0) -> list[dict[str, Any]]:
    sqs = ctx.client("sqs")
    out: list[dict[str, Any]] = []
    deadline = time.monotonic() + max_wait_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            out.append(json.loads(msg["Body"]))
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return out


def _create_lambda_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cfevt-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = ctx.unique_name("sim2real-cfevt-policy-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "sqs:SendMessage"],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


_FORWARDER_SOURCE = textwrap.dedent(
    """
    import json
    import os
    import boto3

    def handler(event, context):
        sqs = boto3.client("sqs")
        body = {"label": os.environ["LABEL"], "event": event}
        sqs.send_message(QueueUrl=os.environ["TARGET_QUEUE_URL"], MessageBody=json.dumps(body))
        return {"ok": True}
    """
)


def _zip_lambda_code(source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", source)
    return buf.getvalue()


def _create_forwarder_lambda(ctx, role_arn: str, queue_url: str, label: str) -> tuple[str, str]:
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name(f"sim2real-cfevt-{label}-")
    code = _zip_lambda_code(_FORWARDER_SOURCE)
    last_err = None
    fn_arn = None
    # IAM role propagation lag: retry (bounded) rather than sleep unconditionally before the first attempt.
    for _ in range(8):
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": code},
                Timeout=30,
                Environment={"Variables": {"TARGET_QUEUE_URL": queue_url, "LABEL": label}},
                Tags={"sim2real": CHECK},
            )
            fn_arn = resp["FunctionArn"]
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(5)
    else:
        raise last_err
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=fn_name)["State"],
        lambda s: s == "Active",
        timeout_s=60,
        interval_s=2.0,
        description=f"lambda {fn_name} Active",
    )
    return fn_name, fn_arn


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
