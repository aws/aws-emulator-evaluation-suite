"""obs-opensearch-2-searchable-documents-metric-crosses-threshold-and-alarm-notifies-sqs."""
from __future__ import annotations

import json
import random
import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

CHECK = "obs-opensearch-2-searchable-documents-metric-crosses-threshold-and-alarm-notifies-sqs"
GROUP = 'alerting'
SERVICES = ['cloudwatch', 'opensearch', 'sns', 'sqs']

ENGINE_VERSION = "OpenSearch_2.11"
# Smallest legal single-node topology: domains bill per node-hour.
MIN_CLUSTER_CONFIG = {
    "InstanceType": "t3.small.search",
    "InstanceCount": 1,
    "DedicatedMasterEnabled": False,
    "ZoneAwarenessEnabled": False,
}
MIN_EBS_OPTIONS = {"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10}
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")
_POLL_S = 2.0

# Marks a published domain endpoint that then failed to answer as a fidelity failure.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _delete_domain_quietly(osc, domain_name: str) -> None:
    """Delete the domain, tolerating one that was never created or is already gone."""
    try:
        osc.delete_domain(DomainName=domain_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _account_access_policy(account_id: str, region: str, domain_name: str) -> str:
    """Resource-based policy letting this account's principals use the data plane."""
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "es:*",
            "Resource": f"arn:aws:es:{region}:{account_id}:domain/{domain_name}/*",
        }],
    })


def _create_min_domain(ctx, account_id: str, *, scenario: str) -> str:
    """Create the cheapest legal domain, cleanup registered BEFORE the create call."""
    osc = ctx.client("opensearch")
    domain_name = ctx.unique_name("sim2real-xsvc-os-")[:28].rstrip("-")
    ctx.on_cleanup(lambda: _delete_domain_quietly(osc, domain_name))
    kwargs = dict(
        DomainName=domain_name,
        EngineVersion=ENGINE_VERSION,
        ClusterConfig=dict(MIN_CLUSTER_CONFIG),
        EBSOptions=dict(MIN_EBS_OPTIONS),
        AccessPolicies=_account_access_policy(account_id, ctx.region, domain_name),
        TagList=[{"Key": "sim2real", "Value": scenario}],
    )
    # CreateDomain is aggressively rate limited per account: back off on throttling.
    for attempt in range(12):
        try:
            osc.create_domain(**kwargs)
            return domain_name
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            time.sleep(6.0 * (1 + attempt) + random.uniform(0, 6.0))
    raise AssertionError("CreateDomain still throttled after 12 attempts")


def _wait_searchable(ctx, domain_name: str, timeout_s: float = 1200.0) -> str:
    """Poll to Processing=False AND a published Endpoint; never a bare sleep."""
    osc = ctx.client("opensearch")
    budget = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + budget
    last: dict = {}
    while time.monotonic() < deadline:
        last = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        if last.get("Processing") is False and last.get("Endpoint"):
            return last["Endpoint"]
        time.sleep(_POLL_S)
    if _budget_spent(ctx):
        raise TimeoutError(f"domain {domain_name} publishing a searchable endpoint: the run budget "
                           "ended first; not graded")
    raise AssertionError(
        f"domain {domain_name} did not publish a searchable endpoint within {budget}s "
        f"(Processing={last.get('Processing')}, Endpoint={last.get('Endpoint')})"
    )


def _signed_request(ctx, method, url, *, body=None, raw=None, content_type="application/json"):
    """SigV4-signed ('es') HTTPS request to a domain endpoint -> (status, parsed_json).

    Signs with ctx's credentials, not boto3's ambient chain: the wrong principal gets a 403."""
    signer_creds = ctx.client("opensearch")._request_signer._credentials
    if signer_creds is None:
        raise AssertionError("no AWS credentials available to sign OpenSearch data-plane requests")
    frozen = signer_creds.get_frozen_credentials()
    if raw is not None:
        data = raw if isinstance(raw, bytes) else raw.encode()
    elif body is not None:
        data = json.dumps(body).encode()
    else:
        data = None
    headers = {"Content-Type": content_type} if data is not None else {}
    aws_req = AWSRequest(method=method, url=url, data=data, headers=headers)
    SigV4Auth(frozen, "es", ctx.region).add_auth(aws_req)
    req = urllib.request.Request(url, data=data, method=method, headers=dict(aws_req.headers))
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            text = resp.read().decode()
            return resp.status, (json.loads(text) if text else {})
    except urllib.error.HTTPError as exc:
        text = exc.read().decode(errors="replace")
        try:
            return exc.code, json.loads(text)
        except ValueError:
            return exc.code, {"raw": text}
    except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:  # the endpoint did not answer
        raise AssertionError(
            f"{DATAPLANE_MARKER}: signed {method} to the domain endpoint did not complete: "
            f"{type(exc).__name__}: {exc}"
        ) from exc


def _wait_data_plane_ready(ctx, base: str, timeout_s: float = 300.0) -> None:
    """Poll a cheap GET until it stops answering 403: the data-plane authorizer can lag the
    access policy after Processing=False and a published Endpoint."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status, _ = _signed_request(ctx, "GET", f"{base}/")
        if status != 403:
            return
        time.sleep(_POLL_S)
    if _budget_spent(ctx):
        raise TimeoutError(f"the domain data plane at {base} answering without 403: the run budget "
                           "ended first; not graded")
    raise AssertionError(
        f"domain data plane still answered 403 after {timeout_s}s (last status {status})"
    )


def _sns_to_sqs(ctx, scenario: str) -> tuple:
    """A topic whose notifications land in a queue we own (SNS envelope kept). -> (arn, url)."""
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-xsvc-osobs-")[:80],
        Tags=[{"Key": "sim2real", "Value": scenario}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-xsvc-osobs-")[:80],
        tags={"sim2real": scenario})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    # Without this policy SNS is not allowed to SendMessage into the queue.
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
        }]})})
    subscription = sns.subscribe(
        TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn,
        ReturnSubscriptionArn=True)["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=subscription))
    return topic_arn, queue_url


def _alarm(cw, name: str) -> dict:
    alarms = cw.describe_alarms(AlarmNames=[name], AlarmTypes=["MetricAlarm"])["MetricAlarms"]
    assert len(alarms) == 1, f"DescribeAlarms for {name!r} returned {len(alarms)!r} alarms: {alarms!r}"
    return alarms[0]


def _wait_alarm_state(ctx, cw, name: str, want: str, timeout_s: float) -> dict:
    """Poll DescribeAlarms (the observable) until StateValue == want, bounded."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        last = _alarm(cw, name)
        if last["StateValue"] == want:
            return last
        time.sleep(_POLL_S)
    if _budget_spent(ctx):
        raise TimeoutError(f"alarm {name!r} reaching {want!r}: the run budget ended first; not graded")
    raise AssertionError(
        f"alarm {name!r} did not reach {want!r} within {timeout_s}s; last state "
        f"{last.get('StateValue')!r} reason {last.get('StateReason')!r}"
    )


def _state_updates(cw, name: str) -> list:
    """Every StateUpdate history item for the alarm, paginated."""
    items: list = []
    for page in cw.get_paginator("describe_alarm_history").paginate(
            AlarmName=name, HistoryItemType="StateUpdate"):
        items.extend(page.get("AlarmHistoryItems", []))
    return items


def _receive_alarm_notification(ctx, queue_url: str, alarm_name: str, deadline_s: float):
    """Drain the queue until the CloudWatch notification for alarm_name arrives -> (body, message).

    The SNS envelope is kept (no raw delivery), so the body is SNS JSON whose `Message` is the
    CloudWatch alarm notification JSON; both are parsed structurally.
    """
    sqs = ctx.client("sqs")
    deadline_s = _budget_s(ctx, deadline_s)
    deadline = time.monotonic() + deadline_s
    seen: list = []
    while time.monotonic() < deadline:
        wait_s = int(max(0.0, min(10.0, deadline - time.monotonic())))
        received = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s)
        for message in received.get("Messages") or []:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"])
            body = json.loads(message["Body"])
            seen.append(body)
            if body.get("Type") != "Notification":
                continue
            inner = json.loads(body["Message"])
            if inner.get("AlarmName") == alarm_name:
                return body, inner
    if _budget_spent(ctx):
        raise TimeoutError(f"the SNS notification for alarm {alarm_name!r}: the run budget ended first; "
                           "not graded")
    raise AssertionError(
        f"no SNS notification for alarm {alarm_name!r} reached the subscribed queue within "
        f"{deadline_s}s; bodies seen: {seen!r}")


_SCENARIO = "obs-opensearch-searchable-documents-alarm"
_THRESHOLD = 10.0
_N_DOCS = 10


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/opensearch-service/latest/developerguide/managedomains-cloudwatchmetrics.html
@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:e2e",
      "concern:eventing", "concern:metrics", "dp:endpoint", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Indexing documents moves the domain's AWS/ES SearchableDocuments metric across a CloudWatch
    alarm threshold; the alarm goes OK -> ALARM on its own, records it, and notifies SQS via SNS.

    Reference: https://docs.aws.amazon.com/opensearch-service/latest/developerguide/managedomains-cloudwatchmetrics.html"""
    cw = ctx.client("cloudwatch")
    sqs = ctx.client("sqs")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    topic_arn, queue_url = _sns_to_sqs(ctx, _SCENARIO)

    domain = _create_min_domain(ctx, account_id, scenario=_SCENARIO)
    base = ctx.endpoint_url(_wait_searchable(ctx, domain))
    _wait_data_plane_ready(ctx, base)

    alarm_name = ctx.unique_name("sim2real-xsvc-osobs-alarm-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        AlarmDescription=f"sim2real {_SCENARIO}",
        Namespace="AWS/ES",
        MetricName="SearchableDocuments",
        Dimensions=[{"Name": "ClientId", "Value": account_id},
                    {"Name": "DomainName", "Value": domain}],
        Statistic="Maximum",
        Period=60,
        EvaluationPeriods=1,
        Threshold=_THRESHOLD,
        ComparisonOperator="GreaterThanOrEqualToThreshold",
        # A one-minute gap in the domain's emitted metric must not bounce OK -> INSUFFICIENT_DATA:
        # the transition graded below is OK -> ALARM, driven by data, not by a missing datapoint.
        TreatMissingData="ignore",
        AlarmActions=[topic_arn],
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    initial = _alarm(cw, alarm_name)
    assert initial["StateValue"] != "ALARM", (
        f"a freshly created alarm on a domain holding no documents is already ALARM: "
        f"{initial.get('StateReason')!r}")
    assert initial["AlarmActions"] == [topic_arn], (
        f"the stored AlarmActions are {initial['AlarmActions']!r}, expected [{topic_arn!r}]")

    # OK before indexing makes the later ALARM attributable to the indexed documents.
    ok = _wait_alarm_state(ctx, cw, alarm_name, "OK", timeout_s=600.0)
    assert ok["StateValue"] == "OK", f"alarm state is {ok['StateValue']!r}, expected 'OK'"

    index = "sim2real-xsvc-osobs"
    status, created = _signed_request(ctx, "PUT", f"{base}/{index}", body={
        "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
        "mappings": {"properties": {"n": {"type": "integer"}}}})
    assert status == 200, f"creating index {index!r} returned HTTP {status!r}: {created!r}"
    ctx.on_cleanup(lambda: _signed_request(ctx, "DELETE", f"{base}/{index}"))

    lines = []
    for i in range(_N_DOCS):
        lines.append(json.dumps({"index": {"_index": index, "_id": f"d{i}"}}))
        lines.append(json.dumps({"n": i}))
    status, bulk = _signed_request(ctx, "POST", f"{base}/_bulk?refresh=true",
                                   raw="\n".join(lines) + "\n",
                                   content_type="application/x-ndjson")
    assert status == 200, f"_bulk returned HTTP {status!r}, expected 200: {bulk!r}"
    assert bulk.get("errors") is False, f"_bulk reported per-item errors: {bulk!r}"
    status, counted = _signed_request(ctx, "GET", f"{base}/{index}/_count")
    assert status == 200, f"_count returned HTTP {status!r}: {counted!r}"
    assert counted.get("count") == _N_DOCS, (
        f"the index holds {counted.get('count')!r} documents after _bulk, expected {_N_DOCS!r}")

    # The metric path: the domain's emitted document count must drive the alarm into ALARM.
    alarmed = _wait_alarm_state(ctx, cw, alarm_name, "ALARM", timeout_s=900.0)
    assert alarmed["StateValue"] == "ALARM", (
        f"alarm state is {alarmed['StateValue']!r}, expected 'ALARM'")

    to_alarm = []
    for item in _state_updates(cw, alarm_name):
        data = json.loads(item["HistoryData"])
        if data.get("newState", {}).get("stateValue") == "ALARM":
            to_alarm.append(data)
    assert len(to_alarm) == 1, (
        f"expected exactly one StateUpdate into ALARM in the alarm history, found {len(to_alarm)!r}: "
        f"{to_alarm!r}")
    assert to_alarm[0]["oldState"]["stateValue"] == "OK", (
        f"the ALARM transition came from {to_alarm[0]['oldState']['stateValue']!r}, expected 'OK'")
    reason = to_alarm[0]["newState"]["stateReason"]
    assert "threshold (10.0)" in reason, (
        f"the StateUpdate reason does not name the 10.0 threshold it crossed: {reason!r}")

    envelope, notification = _receive_alarm_notification(ctx, queue_url, alarm_name, deadline_s=300.0)
    assert envelope["TopicArn"] == topic_arn, (
        f"the queued notification came from topic {envelope['TopicArn']!r}, expected {topic_arn!r}")
    assert notification["NewStateValue"] == "ALARM", (
        f"the delivered notification's NewStateValue is {notification['NewStateValue']!r}")
    assert notification["AlarmName"] == alarm_name, (
        f"the delivered notification names alarm {notification['AlarmName']!r}")
    trigger = notification["Trigger"]
    assert (trigger["Namespace"], trigger["MetricName"]) == ("AWS/ES", "SearchableDocuments"), (
        f"the notification's trigger is {trigger!r}, expected AWS/ES SearchableDocuments")
    dims = {d["name"]: d["value"] for d in trigger["Dimensions"]}
    assert dims == {"ClientId": account_id, "DomainName": domain}, (
        f"the notification's trigger dimensions are {dims!r}")

    # Exactly one transition into ALARM, so exactly one notification: nothing else is queued.
    leftover = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
    assert not leftover.get("Messages"), (
        f"the queue holds further messages after the single ALARM notification: "
        f"{[m['Body'] for m in leftover['Messages']]!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
