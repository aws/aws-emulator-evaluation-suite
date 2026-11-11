"""obs-apigateway-1-5xx-alarm-ok-to-alarm-notifies-sqs-via-sns."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-apigateway-1-5xx-alarm-ok-to-alarm-notifies-sqs-via-sns"
GROUP = "metrics-and-alarms"
SERVICES = ["apigateway", "cloudwatch", "lambda"]

_DEADLINE_S = 600
_BURST = 3

# ===== helpers =====
_TAG_KEY = "sim2real"
_NS = "AWS/ApiGateway"

_HANDLER = r'''
def handler(event, context):
    if (event.get("path") or "").endswith("/boom"):
        return {"statusCode": 500, "body": "LAMBDA-500"}
    return {"statusCode": 200, "body": "LAMBDA-200"}
'''


class _Deadline:
    """One wall-clock budget for the whole check. Exceeding it RAISES, naming the phase."""

    def __init__(self, seconds):
        self.seconds = seconds
        self.end = time.monotonic() + seconds

    def left(self, phase):
        rem = self.end - time.monotonic()
        if rem <= 0:
            raise AssertionError(f"{_DEADLINE_S}s check deadline exceeded during: {phase}")
        return rem


def _poll_until(probe, predicate, *, deadline, timeout_s, interval_s=5.0, description="cond"):
    """Bounded retry under BOTH a local timeout and the check deadline; RAISES on either."""
    end = time.monotonic() + min(timeout_s, deadline.left(description))
    last = None
    while time.monotonic() < end:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s (or the {_DEADLINE_S}s "
                         f"check deadline). Last result: {last!r}")


#: Not-found codes of the deletes wrapped by _quiet: IAM, Lambda, CloudWatch, SQS, SNS.
_GONE = {"NoSuchEntity", "ResourceNotFoundException", "ResourceNotFound",
         "AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist", "NotFound"}


def _quiet(fn):
    """Teardown: a resource that is already gone is clean; any other failure raises."""
    def _wrapped():
        try:
            fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in _GONE:
                raise
    return _wrapped


def _throttled(fn, attempts=12):
    """API Gateway mutating calls are rate limited account-wide; retry only that code."""
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "TooManyRequestsException" or \
                    attempt == attempts - 1:
                raise
            time.sleep(min(10.0, 0.5 * (2 ** attempt)))
    raise AssertionError("unreachable")


def _teardown(fn):
    """Teardown: retry throttles, tolerate NotFound, and raise on anything else."""
    def _wrapped():
        for _ in range(12):
            try:
                fn()
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "NotFoundException":
                    return
                if code != "TooManyRequestsException":
                    raise RuntimeError(f"teardown failed: {code}") from exc
                time.sleep(10)
        raise RuntimeError("teardown still throttled after 12 attempts")
    return _wrapped


def _http(url, timeout=30):
    req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _lambda(ctx, deadline):
    """A python3.12 function whose role has NO logs permissions, so no log group is ever made."""
    iam, lam = ctx.client("iam"), ctx.client("lambda")
    name = ctx.unique_name("sim2real-xsvc-al-")
    role_arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole",
                                                 "Principal": {"Service": "lambda.amazonaws.com"}}]}),
        Tags=[{"Key": _TAG_KEY, "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(_quiet(lambda: iam.delete_role(RoleName=name)))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", _HANDLER)

    def _create():
        try:
            return lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn, Handler="index.handler",
                Code={"ZipFile": buf.getvalue()}, Timeout=10, Tags={_TAG_KEY: CHECK})
        except ClientError as exc:
            # A freshly created role is not assumable for a few seconds (IAM propagation).
            if exc.response["Error"]["Code"] == "InvalidParameterValueException":
                return None
            raise

    fn = _poll_until(_create, lambda r: r is not None, deadline=deadline, timeout_s=90,
                     description="lambda.create_function accepting the new role")
    ctx.on_cleanup(_quiet(lambda: lam.delete_function(FunctionName=name)))
    _poll_until(lambda: lam.get_function(FunctionName=name)["Configuration"]["State"],
                lambda s: s == "Active", deadline=deadline, timeout_s=120, interval_s=2,
                description="lambda function Active")
    return name, fn["FunctionArn"]


def _rest_api(ctx, name, fn_name, fn_arn, lambda_path):
    """REST API with GET /<lambda_path> -> AWS_PROXY lambda and GET /ready -> MOCK 200,
    deployed to stage `live`. Readiness traffic uses /ready so it never produces a 5xx."""
    apigw = ctx.client("apigateway")
    api_id = _throttled(lambda: apigw.create_rest_api(
        name=name, description=f"sim2real {CHECK}",
        endpointConfiguration={"types": ["REGIONAL"]}, tags={_TAG_KEY: CHECK}))["id"]
    ctx.on_cleanup(_teardown(lambda: apigw.delete_rest_api(restApiId=api_id)))
    root = next(r["id"] for r in apigw.get_resources(restApiId=api_id)["items"] if r["path"] == "/")
    acct = ctx.client("sts").get_caller_identity()["Account"]
    ctx.client("lambda").add_permission(
        FunctionName=fn_name, StatementId=f"apigw-{api_id}", Action="lambda:InvokeFunction",
        Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:aws:execute-api:{ctx.region}:{acct}:{api_id}/*")
    res = _throttled(lambda: apigw.create_resource(
        restApiId=api_id, parentId=root, pathPart=lambda_path))["id"]
    _throttled(lambda: apigw.put_method(restApiId=api_id, resourceId=res, httpMethod="GET",
                                        authorizationType="NONE"))
    _throttled(lambda: apigw.put_integration(
        restApiId=api_id, resourceId=res, httpMethod="GET", type="AWS_PROXY",
        integrationHttpMethod="POST",
        uri=(f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/{fn_arn}"
             f"/invocations")))
    rdy = _throttled(lambda: apigw.create_resource(
        restApiId=api_id, parentId=root, pathPart="ready"))["id"]
    _throttled(lambda: apigw.put_method(restApiId=api_id, resourceId=rdy, httpMethod="GET",
                                        authorizationType="NONE"))
    _throttled(lambda: apigw.put_integration(
        restApiId=api_id, resourceId=rdy, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'}))
    _throttled(lambda: apigw.put_method_response(
        restApiId=api_id, resourceId=rdy, httpMethod="GET", statusCode="200"))
    _throttled(lambda: apigw.put_integration_response(
        restApiId=api_id, resourceId=rdy, httpMethod="GET", statusCode="200",
        selectionPattern="", responseTemplates={"application/json": '{"ready": true}'}))
    _throttled(lambda: apigw.create_deployment(restApiId=api_id, stageName="live"))
    return ctx.rest_api_url(api_id, 'live')


def _ready(urls, deadline, quiet_s=30):
    """Stage propagation is eventual and per-node: wait for a quiet window of only 200s."""
    streak_from = None
    last = None
    end = time.monotonic() + min(240, deadline.left("stage readiness"))
    while time.monotonic() < end:
        last = [(u, _http(u)[0]) for u in urls]
        now = time.monotonic()
        streak_from = (streak_from or now) if all(c == 200 for _u, c in last) else None
        if streak_from is not None and now - streak_from >= quiet_s:
            return
        time.sleep(0.5)
    raise AssertionError(f"no {quiet_s}s window of 200s from {urls!r}; last {last!r}")


def _dims(**kv):
    return [{"Name": k, "Value": v} for k, v in kv.items()]


def _alarm(ctx, name, dims, topic_arn):
    cw = ctx.client("cloudwatch")
    cw.put_metric_alarm(
        AlarmName=name, AlarmDescription=f"sim2real {CHECK}", Namespace=_NS,
        MetricName="5XXError", Dimensions=dims, Statistic="Sum", Period=60,
        EvaluationPeriods=1, Threshold=1.0, ComparisonOperator="GreaterThanOrEqualToThreshold",
        TreatMissingData="notBreaching", AlarmActions=[topic_arn],
        Tags=[{"Key": _TAG_KEY, "Value": CHECK}])
    ctx.on_cleanup(_quiet(lambda: cw.delete_alarms(AlarmNames=[name])))


def _state(ctx, name):
    alarms = ctx.client("cloudwatch").describe_alarms(AlarmNames=[name])["MetricAlarms"]
    assert len(alarms) == 1, f"describe_alarms({name!r}) returned {len(alarms)} alarms"
    return alarms[0]["StateValue"]


def _transitions(ctx, name):
    """Every StateUpdate in the alarm's history as (old, new, reason), oldest first."""
    cw = ctx.client("cloudwatch")
    out = []
    for page in cw.get_paginator("describe_alarm_history").paginate(
            AlarmName=name, HistoryItemType="StateUpdate", ScanBy="TimestampAscending"):
        for item in page["AlarmHistoryItems"]:
            data = json.loads(item["HistoryData"])
            out.append((data.get("oldState", {}).get("stateValue"),
                        data.get("newState", {}).get("stateValue"),
                        data.get("newState", {}).get("stateReason")))
    return out
# ===== end helpers =====


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:eventing",
    "concern:metrics",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
    "timing:real-time",
)
def run(ctx) -> None:
    """Real 500s from a REST API stage move a 5XXError {ApiName, Stage} alarm OK -> ALARM, recorded in
    alarm history and notified through SNS to SQS; a control API serving only 200s with an identical
    alarm on the same topic reaches OK, never alarms and delivers no notification."""
    deadline = _Deadline(_DEADLINE_S)
    sqs, sns, cw = ctx.client("sqs"), ctx.client("sns"), ctx.client("cloudwatch")

    # ---- SNS -> SQS wiring, proven with a canary before any alarm exists ----
    qname = ctx.unique_name("sim2real-xsvc-alq-")
    q_url = sqs.create_queue(QueueName=qname, tags={_TAG_KEY: CHECK})["QueueUrl"]
    ctx.on_cleanup(_quiet(lambda: sqs.delete_queue(QueueUrl=q_url)))
    q_arn = sqs.get_queue_attributes(QueueUrl=q_url,
                                     AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-xsvc-alt-"),
                                 Tags=[{"Key": _TAG_KEY, "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(_quiet(lambda: sns.delete_topic(TopicArn=topic_arn)))
    sqs.set_queue_attributes(QueueUrl=q_url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": q_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}}}]})})
    sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=q_arn,
                            ReturnSubscriptionArn=True)["SubscriptionArn"]
    ctx.on_cleanup(_quiet(lambda: sns.unsubscribe(SubscriptionArn=sub_arn)))

    inbox: list[dict] = []

    def _drain():
        resp = sqs.receive_message(QueueUrl=q_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for m in resp.get("Messages", []):
            inbox.append(json.loads(m["Body"]))
            sqs.delete_message(QueueUrl=q_url, ReceiptHandle=m["ReceiptHandle"])
        return list(inbox)

    canary = ctx.unique_name("canary-")
    sns.publish(TopicArn=topic_arn, Message=canary)
    _poll_until(_drain, lambda msgs: any(e.get("Message") == canary for e in msgs),
                deadline=deadline, timeout_s=90, interval_s=0,
                description="the SNS canary arriving in the subscribed SQS queue")

    # ---- the APIs: one that 500s at /boom, one that only ever answers 200 ----
    fn_name, fn_arn = _lambda(ctx, deadline)
    api_name = ctx.unique_name("sim2real-xsvc-al5xx-")
    ctl_name = ctx.unique_name("sim2real-xsvc-alctl-")
    base = _rest_api(ctx, api_name, fn_name, fn_arn, "boom")
    ctl_base = _rest_api(ctx, ctl_name, fn_name, fn_arn, "ok")
    _ready([f"{base}/ready", f"{ctl_base}/ready", f"{ctl_base}/ok"], deadline)
    started = datetime.now(timezone.utc) - timedelta(minutes=5)

    dims = _dims(ApiName=api_name, Stage="live")
    ctl_dims = _dims(ApiName=ctl_name, Stage="live")
    alarm = ctx.unique_name("sim2real-xsvc-5xx-")
    ctl_alarm = ctx.unique_name("sim2real-xsvc-5xxctl-")
    _alarm(ctx, alarm, dims, topic_arn)
    _alarm(ctx, ctl_alarm, ctl_dims, topic_arn)

    _poll_until(lambda: (_state(ctx, alarm), _state(ctx, ctl_alarm)),
                lambda s: s == ("OK", "OK"), deadline=deadline, timeout_s=240,
                interval_s=5, description="both alarms reaching OK")

    # ---- drive 500s until the alarm fires; keep the control serving 200s throughout ----
    sent = {"500": 0, "200": 0}
    ctl_seen = set()
    while True:
        deadline.left("driving 5xx until the alarm enters ALARM")
        for _ in range(_BURST):
            st, body = _http(f"{base}/boom")
            assert (st, body) == (500, b"LAMBDA-500"), (
                f"GET /boom must return the integration's own 500, got {st} {body[:120]!r}")
            sent["500"] += 1
            st, body = _http(f"{ctl_base}/ok")
            assert (st, body) == (200, b"LAMBDA-200"), f"control GET /ok -> {st} {body[:120]!r}"
            sent["200"] += 1
        state, ctl_state = _state(ctx, alarm), _state(ctx, ctl_alarm)
        ctl_seen.add(ctl_state)
        if state == "ALARM":
            break
        time.sleep(15)

    hist = _poll_until(lambda: _transitions(ctx, alarm),
                       lambda h: any(o == "OK" and n == "ALARM" for o, n, _r in h),
                       deadline=deadline, timeout_s=120,
                       description="an OK->ALARM StateUpdate in DescribeAlarmHistory")
    ok_to_alarm = [r for o, n, r in hist if (o, n) == ("OK", "ALARM")]
    assert ok_to_alarm and (ok_to_alarm[0] or "").startswith("Threshold Crossed"), (
        f"the OK->ALARM StateUpdate must carry a 'Threshold Crossed' StateReason; history {hist!r}")

    def _alarm_notes(msgs, name):
        out = []
        for env in msgs:
            if env.get("TopicArn") != topic_arn:
                continue
            try:
                body = json.loads(env.get("Message") or "")
            except ValueError:
                continue
            if isinstance(body, dict) and body.get("AlarmName") == name:
                out.append(body)
        return out

    msgs = _poll_until(_drain, lambda m: bool(_alarm_notes(m, alarm)), deadline=deadline,
                       timeout_s=120, interval_s=0,
                       description="the ALARM notification arriving in SQS via SNS")
    note = _alarm_notes(msgs, alarm)[0]
    trig = note.get("Trigger", {})
    got = (note.get("NewStateValue"), note.get("OldStateValue"), trig.get("MetricName"),
           trig.get("Namespace"),
           sorted((d.get("name"), d.get("value")) for d in trig.get("Dimensions", [])))
    want = ("ALARM", "OK", "5XXError", _NS, [("ApiName", api_name), ("Stage", "live")])
    assert got == want, f"SNS->SQS alarm notification {got!r}, expected {want!r}; body {note!r}"

    # ---- control: stayed OK on real zeros, and published nothing ----
    ctl_state = _state(ctx, ctl_alarm)
    ctl_seen.add(ctl_state)
    ctl_hist = _transitions(ctx, ctl_alarm)
    assert ctl_seen == {"OK"} and all(n != "ALARM" for _o, n, _r in ctl_hist), (
        f"the 200-only control alarm must stay OK throughout; states seen {sorted(ctl_seen)!r}, "
        f"history {ctl_hist!r}")
    zeros = _poll_until(
        lambda: cw.get_metric_statistics(
            Namespace=_NS, MetricName="5XXError", Dimensions=ctl_dims, StartTime=started,
            EndTime=datetime.now(timezone.utc) + timedelta(minutes=3), Period=60,
            Statistics=["Sum", "SampleCount"])["Datapoints"],
        lambda pts: sum(p["SampleCount"] for p in pts) >= sent["200"], deadline=deadline,
        timeout_s=180, interval_s=10,
        description=f"control 5XXError SampleCount reaching the {sent['200']} 200s sent")
    ctl_sum = sum(p["Sum"] for p in zeros)
    assert ctl_sum == 0, f"control 5XXError must be published as zeros, summed to {ctl_sum}"
    stray = _alarm_notes(_drain(), ctl_alarm)
    assert stray == [], f"the control alarm must deliver no notification, got {stray!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
