"""obs-apigatewayv2-3-http-api-5xx-alarm-actions-disabled-notification-blocked."""

from __future__ import annotations

import datetime as dt
import json
import textwrap
import time
import urllib.error
import urllib.request
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-apigatewayv2-3-http-api-5xx-alarm-actions-disabled-notification-blocked"

GROUP = "observability"

SERVICES = ["apigatewayv2", "cloudwatch"]

_HANDLER = """
import os


def lambda_handler(event, context):
    return {
        "statusCode": 500,
        "headers": {"Content-Type": "text/plain"},
        "body": os.environ["MARKER"],
    }
"""

_STAGE = "live"
_ROUTE_KEY = "GET /boom"
_THRESHOLD = 3.0
_REQUESTS = 5
_SETTLE_STREAK = 3
_ALARM_WAIT_S = 360.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags(
    "axis:negative-delivery",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:eventing",
    "concern:metrics",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """An actions-disabled alarm still EVALUATES real gateway 5xx traffic into ALARM but never
    notifies, while its enabled twin on the same series and topic does; after EnableAlarmActions
    the same queue receives its notification, so the absence was the flag, not the wiring."""
    marker = ctx.unique_name("sim2real-xsvc-5xx-")
    account = _account_id(ctx)
    fn = _create_lambda(ctx, _HANDLER, env={"MARKER": marker})

    agw = ctx.client("apigatewayv2")
    created_api = agw.create_api(
        Name=_xname(ctx, "httpapi-5xx"), ProtocolType="HTTP", Tags=_xsvc_resource_tags()
    )
    api_id, api_endpoint = created_api["ApiId"], created_api["ApiEndpoint"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=api_id))
    integration_id = agw.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationUri=fn["arn"],
        IntegrationMethod="POST",
        PayloadFormatVersion="2.0",
    )["IntegrationId"]
    agw.create_route(ApiId=api_id, RouteKey=_ROUTE_KEY, Target=f"integrations/{integration_id}")
    agw.create_stage(ApiId=api_id, StageName=_STAGE, AutoDeploy=True)
    ctx.on_cleanup(
        lambda: ctx.client("apigatewayv2").delete_stage(ApiId=api_id, StageName=_STAGE)
    )
    _allow_apigw_invoke(
        ctx, fn["name"], f"arn:aws:execute-api:{ctx.region}:{account}:{api_id}/*/*"
    )

    topic_arn, queue_url = _sns_to_sqs(ctx, account)

    cw = ctx.client("cloudwatch")
    dimensions = [{"Name": "ApiId", "Value": api_id}, {"Name": "Stage", "Value": _STAGE}]
    control = _xname(ctx, "alarm-5xx-on")
    muted = _xname(ctx, "alarm-5xx-off")
    for alarm_name, enabled in ((control, True), (muted, False)):
        cw.put_metric_alarm(
            AlarmName=alarm_name,
            AlarmDescription=f"sim2real {CHECK}",
            Namespace="AWS/ApiGateway",
            MetricName="5xx",
            Dimensions=dimensions,
            Statistic="Sum",
            Period=60,
            EvaluationPeriods=1,
            Threshold=_THRESHOLD,
            ComparisonOperator="GreaterThanOrEqualToThreshold",
            TreatMissingData="notBreaching",
            ActionsEnabled=enabled,
            AlarmActions=[topic_arn],
            Tags=_xsvc_tags_kv(),
        )
        ctx.on_cleanup(
            lambda n=alarm_name: ctx.client("cloudwatch").delete_alarms(AlarmNames=[n])
        )
    assert _describe_alarm(cw, control).get("ActionsEnabled") is True, (
        f"the control alarm must have actions enabled: {_describe_alarm(cw, control)!r}"
    )
    stored_muted = _describe_alarm(cw, muted)
    assert stored_muted.get("ActionsEnabled") is False, (
        f"the muted alarm must store ActionsEnabled=False, got {stored_muted.get('ActionsEnabled')!r}"
    )
    assert stored_muted.get("AlarmActions") == [topic_arn], (
        f"the muted alarm must still carry the SAME topic action (only the flag differs), got "
        f"{stored_muted.get('AlarmActions')!r}"
    )

    # Settle the stage on consecutive 500s from THIS backend (a single 500 can come from one edge
    # while another still serves the pre-deployment 404), then send the counted batch.
    url = _v2_invoke_url(ctx, api_endpoint, _STAGE, "/boom")
    streak = 0
    deadline = time.monotonic() + 150.0
    while streak < _SETTLE_STREAK:
        try:
            status, _, text = _http("GET", url)
        except OSError as exc:  # execute-api DNS/TLS still settling
            status, text = None, f"connection error: {exc}"
        if status == 500:
            assert text == marker, (
                f"the settling 500 must come from this check's integration (marker {marker!r}), "
                f"got {text[:200]!r}"
            )
            streak += 1
            continue
        streak = 0
        assert time.monotonic() < deadline, (
            f"GET /boom on stage {_STAGE} ({url}) never served {_SETTLE_STREAK} consecutive 500s "
            f"within 150s. Last: {status} {text[:300]!r}"
        )
        time.sleep(2.0)
    for i in range(_REQUESTS):
        status, _, text = _http("GET", url)
        assert status == 500 and text == marker, (
            f"request {i + 1}/{_REQUESTS} must be a 500 served by the integration, got {status}: "
            f"{text[:200]!r}"
        )

    # Both alarms evaluate the same breach: the muted one is NOT exempt from evaluation.
    _poll_until(
        ctx,
        lambda: {n: _describe_alarm(cw, n) for n in (control, muted)},
        lambda s: all(a.get("StateValue") == "ALARM" for a in s.values()),
        timeout_s=_ALARM_WAIT_S,
        interval_s=2.0,
        description=(
            f"both the enabled and the actions-disabled 5xx alarm on (ApiId={api_id}, "
            f"Stage={_STAGE}) reaching ALARM on the same breach"
        ),
    )

    # Barrier: the control alarm's notification for the same breach reaches the queue.
    control_notes = _poll_until(
        ctx,
        lambda: _alarm_notifications(ctx, queue_url, control),
        lambda ms: any(m.get("NewStateValue") == "ALARM" for m in ms),
        timeout_s=180.0,
        interval_s=1.0,
        description=f"the ENABLED alarm {control}'s ALARM notification arriving in the queue",
    )
    assert control_notes[0].get("_TopicArn") == topic_arn, (
        f"the control notification must arrive through {topic_arn!r}, got {control_notes[0]!r}"
    )

    leaked = _alarm_notifications(ctx, queue_url, muted)
    assert not leaked, (
        f"an alarm with ActionsEnabled=False must not publish to its AlarmActions topic; the "
        f"queue received {leaked!r} alongside the enabled alarm's notification for the same breach"
    )

    muted_actions = _action_history(cw, muted)
    assert muted_actions == [], (
        f"the actions-disabled alarm must record NO Action history item for its ALARM "
        f"transition, got {muted_actions!r}"
    )
    control_actions = _action_history(cw, control)
    assert any("Successfully executed action" in (h.get("HistorySummary") or "")
               for h in control_actions), (
        f"the enabled alarm's history must record its executed SNS action, got {control_actions!r}"
    )
    muted_updates = [
        h for h in cw.describe_alarm_history(
            AlarmName=muted, HistoryItemType="StateUpdate", MaxRecords=50
        ).get("AlarmHistoryItems", [])
        if "to ALARM" in (h.get("HistorySummary") or "")
    ]
    assert muted_updates, (
        "the actions-disabled alarm's history must still record its transition to ALARM (it is "
        "evaluated, just not actioned)"
    )

    # Repair exactly the one broken thing and re-drive the transition: the same queue must now
    # receive the formerly muted alarm's notification.
    muted_until = _describe_alarm(cw, muted)["StateUpdatedTimestamp"]
    cw.enable_alarm_actions(AlarmNames=[muted])
    assert _describe_alarm(cw, muted).get("ActionsEnabled") is True, (
        "EnableAlarmActions must flip the stored flag"
    )
    cw.set_alarm_state(AlarmName=muted, StateValue="OK", StateReason="sim2real repair: reset")
    cw.set_alarm_state(
        AlarmName=muted, StateValue="ALARM", StateReason="sim2real repair: re-drive with actions"
    )
    repaired = _poll_until(
        ctx,
        lambda: _alarm_notifications(ctx, queue_url, muted),
        lambda ms: any(m.get("NewStateValue") == "ALARM" for m in ms),
        timeout_s=180.0,
        interval_s=1.0,
        description=(
            f"the formerly muted alarm {muted}'s ALARM notification arriving in the SAME queue "
            f"after EnableAlarmActions"
        ),
    )
    assert repaired[0].get("_TopicArn") == topic_arn, (
        f"the repaired alarm's notification must come through {topic_arn!r}, got {repaired[0]!r}"
    )
    # Contrast: the repaired notification is ordered after the muted breach, so a notification
    # leaked by any transition while actions were disabled (server clock) would have arrived first.
    muted_breach = [
        m for m in repaired
        if (dt.datetime.fromisoformat(m["StateChangeTime"]) <= muted_until if m.get("StateChangeTime")
            else m.get("NewStateReason") != "sim2real repair: re-drive with actions")
    ]
    assert not muted_breach, (
        f"an alarm with ActionsEnabled=False must not publish to its AlarmActions topic; the queue "
        f"received {muted_breach!r} for its actions-disabled breach"
    )


def _action_history(cw, alarm_name):
    return cw.describe_alarm_history(
        AlarmName=alarm_name, HistoryItemType="Action", MaxRecords=50
    ).get("AlarmHistoryItems", [])


# ===== helpers =====


_XSVC_PREFIX = "sim2real-xsvc-"


def _xsvc_resource_tags() -> dict:
    return {"sim2real:managed": "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _describe_alarm(cw, alarm_name):
    alarms = cw.describe_alarms(AlarmNames=[alarm_name]).get("MetricAlarms") or []
    assert len(alarms) == 1, f"DescribeAlarms for {alarm_name!r} returned {alarms!r}"
    return alarms[0]


def _sns_to_sqs(ctx, account):
    """A topic and a queue subscribed to it (non-raw, so the SNS envelope survives). Returns
    (topic_arn, queue_url); teardown registered for all three."""
    sqs = ctx.client("sqs")
    sns = ctx.client("sns")
    queue_url = sqs.create_queue(
        QueueName=_xname(ctx, "q-alarm"), tags=_xsvc_resource_tags()
    )["QueueUrl"]
    ctx.on_cleanup(lambda: ctx.client("sqs").delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    topic_arn = sns.create_topic(Name=_xname(ctx, "t-alarm"), Tags=_xsvc_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda: ctx.client("sns").delete_topic(TopicArn=topic_arn))
    sqs.set_queue_attributes(
        QueueUrl=queue_url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "sns.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": queue_arn,
                            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
                        }
                    ],
                }
            )
        },
    )
    sub_arn = sns.subscribe(
        TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn, ReturnSubscriptionArn=True
    )["SubscriptionArn"]
    ctx.on_cleanup(lambda: ctx.client("sns").unsubscribe(SubscriptionArn=sub_arn))
    attrs = sns.get_subscription_attributes(SubscriptionArn=sub_arn)["Attributes"]
    assert attrs.get("PendingConfirmation") == "false", (
        f"a same-account SQS subscription must be confirmed on creation, got {attrs!r}"
    )
    assert account in queue_arn, f"queue ARN {queue_arn!r} is not in account {account!r}"
    return topic_arn, queue_url


_SEEN: dict = {}


def _alarm_notifications(ctx, queue_url, alarm_name):
    """Every alarm notification for `alarm_name` received from the queue so far (accumulated
    across polls, since a received message is deleted). Each is the parsed alarm JSON plus the
    envelope's TopicArn under `_TopicArn`."""
    sqs = ctx.client("sqs")
    seen = _SEEN.setdefault(queue_url, [])
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10)
    for msg in resp.get("Messages", []):
        envelope = json.loads(msg["Body"])
        try:
            body = json.loads(envelope.get("Message") or "")
        except ValueError:
            body = {"_raw": envelope.get("Message")}
        body["_TopicArn"] = envelope.get("TopicArn")
        seen.append(body)
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return [m for m in seen if m.get("AlarmName") == alarm_name]


def _poll_until(ctx, probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result); return it. RAISES on timeout."""
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _http(method, url, body=None, headers=None, timeout_s=20):
    """(status, [(lower_header_name, value)], text). A 4xx/5xx is a RESULT, not an exception."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return (
                resp.status,
                [(k.lower(), v) for k, v in resp.getheaders()],
                resp.read().decode("utf-8", "replace"),
            )
    except urllib.error.HTTPError as exc:
        return (
            exc.code,
            [(k.lower(), v) for k, v in exc.headers.items()],
            exc.read().decode("utf-8", "replace"),
        )


def _v2_invoke_url(ctx, api_endpoint, stage, path):
    """The invoke URL of `path` on an HTTP API stage."""
    return f"{ctx.stage_url(api_endpoint, stage or '$default')}/{path.lstrip('/')}"


def _reap_log_group(ctx, name, settle_s=30.0):
    """Delete a log group in a LOOP: a Lambda log stream buffered by an invocation that already
    returned can flush after the delete and recreate the group. Re-delete until it has stayed gone
    for the settle window; raise rather than hang if it never converges."""
    logs = ctx.client("logs")
    deadline = time.monotonic() + settle_s
    while True:
        try:
            logs.delete_log_group(logGroupName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        if time.monotonic() >= deadline:
            break
        time.sleep(5.0)
    groups = logs.describe_log_groups(logGroupNamePrefix=name).get("logGroups", [])
    if any(g.get("logGroupName") == name for g in groups):
        raise RuntimeError(f"log group {name} reappeared after repeated deletes")


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    iam.delete_role(RoleName=role_name)


def _create_role(ctx, trust_service, inline_policy=None):
    iam = ctx.client("iam")
    role_name = _xname(ctx, f"role-{trust_service.split('.')[0]}")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
        )
    return resp["Role"]["Arn"]


def _create_lambda(ctx, handler_code, env=None, permissions=None, timeout=30):
    """Create a Lambda (role scoped to logs plus `permissions`), retrying through the IAM
    role-propagation window, then wait for Active. The /aws/lambda/<name> reap is registered
    BEFORE the function, so LIFO runs it after the delete."""
    statements = [
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "arn:aws:logs:*:*:*",
        }
    ]
    statements.extend(permissions or [])
    role_arn = _create_role(
        ctx, "lambda.amazonaws.com", {"Version": "2012-10-17", "Statement": statements}
    )

    lam = ctx.client("lambda")
    name = _xname(ctx, "fn")
    ctx.on_cleanup(lambda: _reap_log_group(ctx, f"/aws/lambda/{name}"))
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", textwrap.dedent(handler_code))
    kwargs = {
        "FunctionName": name,
        "Runtime": "python3.12",
        "Role": role_arn,
        "Handler": "lambda_function.lambda_handler",
        "Code": {"ZipFile": buf.getvalue()},
        "Timeout": timeout,
        "MemorySize": 128,
        "Tags": dict(_xsvc_resource_tags()),
    }
    if env:
        kwargs["Environment"] = {"Variables": env}

    def _try_create():
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in (
                "InvalidParameterValueException",
                "AccessDeniedException",
            ):
                return None  # brand-new role not yet assumable by Lambda
            raise

    created = _poll_until(
        ctx,
        _try_create,
        lambda r: r is not None,
        timeout_s=120.0,
        interval_s=2.0,
        description=f"Lambda {name} created once its execution role became assumable",
    )
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function(FunctionName=name))
    _poll_until(
        ctx,
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda c: c.get("State") == "Active",
        timeout_s=120.0,
        interval_s=2.0,
        description=f"Lambda {name} reaching State=Active",
    )
    return {"name": name, "arn": created["FunctionArn"]}


def _allow_apigw_invoke(ctx, fn_name, source_arn, statement_id="apigw-invoke"):
    try:
        ctx.client("lambda").add_permission(
            FunctionName=fn_name,
            StatementId=statement_id,
            Action="lambda:InvokeFunction",
            Principal="apigateway.amazonaws.com",
            SourceArn=source_arn,
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceConflictException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
