"""alerting-monitor-trigger-publishes-the-rendered-count-to-sns-and-withholds-it-when-false."""
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

CHECK = "alerting-monitor-trigger-publishes-the-rendered-count-to-sns-and-withholds-it-when-false"
GROUP = 'event-propagation'
SERVICES = ['opensearch', 'sns', 'sqs']

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

# Marks a published domain endpoint that failed to answer as a target failure.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


def _delete_domain_quietly(osc, domain_name: str) -> None:
    """Idempotent teardown: tolerate a domain that was never created / already deleted."""
    try:
        osc.delete_domain(DomainName=domain_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _account_access_policy(ctx, domain_name: str) -> str:
    """Resource-based policy letting this account's principals use the data plane."""
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "es:*",
            "Resource": f"arn:aws:es:{ctx.region}:{account_id}:domain/{domain_name}/*",
        }],
    })


def _create_min_domain(ctx, *, scenario: str, **overrides) -> str:
    """Create the cheapest legal domain, cleanup registered BEFORE the create call."""
    osc = ctx.client("opensearch")
    domain_name = ctx.unique_name("sim2real-behav-os-")[:28].rstrip("-")
    ctx.on_cleanup(lambda: _delete_domain_quietly(osc, domain_name))
    kwargs = dict(
        DomainName=domain_name,
        EngineVersion=ENGINE_VERSION,
        ClusterConfig=dict(MIN_CLUSTER_CONFIG),
        EBSOptions=dict(MIN_EBS_OPTIONS),
        AccessPolicies=_account_access_policy(ctx, domain_name),
        TagList=[{"Key": "sim2real", "Value": scenario}],
    )
    kwargs.update(overrides)
    # CreateDomain is aggressively rate limited per account: back off, with jitter, on throttling.
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
    budget = timeout_s
    deadline = time.monotonic() + budget
    last: dict = {}
    while time.monotonic() < deadline:
        last = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        if last.get("Processing") is False and last.get("Endpoint"):
            return last["Endpoint"]
        time.sleep(2.0)
    raise AssertionError(
        f"domain {domain_name} did not publish a searchable endpoint within {budget}s "
        f"(Processing={last.get('Processing')}, Endpoint={last.get('Endpoint')})",
    )


def _signed_request(ctx, method, url, *, body=None, raw=None, content_type="application/json"):
    """SigV4-signed ('es') HTTPS request to a domain endpoint -> (status, parsed_json).

    Signs with ctx's credentials, not boto3's ambient chain: the account-scoped policy 403s others.
    """
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
    except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:
        # The target published this endpoint, so a transport failure on it is the target's failure.
        raise AssertionError(
            f"{DATAPLANE_MARKER}: signed {method} to the domain endpoint did not complete: "
            f"{type(exc).__name__}: {exc}"
        ) from exc


def _wait_data_plane_ready(ctx, base: str, timeout_s: float = 300.0) -> None:
    """Poll a cheap GET until signed requests stop returning 403.

    Processing=False and a published Endpoint do not mean the access policy is in effect yet.
    """
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status, _ = _signed_request(ctx, "GET", f"{base}/")
        if status != 403:
            return
        time.sleep(2.0)
    raise AssertionError(
        f"domain data plane still answered 403 after {timeout_s}s (last status {status})",
    )


def _error_type(payload) -> str:
    """OpenSearch engine errors carry {'error': {'type': ..., 'reason': ...}, 'status': n}."""
    error = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(error, dict):
        return str(error.get("type") or "")
    return ""


def _total(result):
    total = result.get("hits", {}).get("total")
    return total.get("value") if isinstance(total, dict) else total


def _hit_ids(result) -> list:
    return [h["_id"] for h in result["hits"]["hits"]]



def _delete_role_quietly(iam, role_name: str) -> None:
    """Detach every inline policy, then delete the role; idempotent."""
    try:
        for name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=name)
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _sns_to_sqs(ctx, scenario: str) -> tuple:
    """A topic whose messages land, raw, in a queue we own. -> (topic_arn, queue_url)."""
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    topic_name = ctx.unique_name("sim2real-behav-osalert-")[:80]
    topic_arn = sns.create_topic(
        Name=topic_name, Tags=[{"Key": "sim2real", "Value": scenario}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    queue_name = ctx.unique_name("sim2real-behav-osalert-")[:80]
    queue_url = sqs.create_queue(
        QueueName=queue_name, tags={"sim2real": scenario})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

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
        TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn, ReturnSubscriptionArn=True,
        # Raw delivery, so the queue body IS the message the monitor rendered -- no SNS envelope to
        # parse and no chance of asserting against SNS's own metadata instead of the payload.
        Attributes={"RawMessageDelivery": "true"})["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=subscription))
    return topic_arn, queue_url


def _publish_role(ctx, scenario: str, topic_arn: str) -> str:
    """An es.amazonaws.com-trusted role that may publish to exactly that topic."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-osalert-")[:64]
    ctx.on_cleanup(lambda: _delete_role_quietly(iam, role_name))
    role = iam.create_role(
        RoleName=role_name,
        Description=f"sim2real {scenario} OpenSearch notifications role",
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"Service": "es.amazonaws.com"},
                           "Action": "sts:AssumeRole"}]}),
        Tags=[{"Key": "sim2real", "Value": scenario}])["Role"]
    iam.put_role_policy(RoleName=role_name, PolicyName="sim2real-sns", PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "sns:Publish", "Resource": topic_arn}]}))
    return role["Arn"]


def _bulk_load(ctx, base: str, index: str, docs) -> None:
    lines = []
    for doc_id, source in docs:
        lines.append(json.dumps({"index": {"_index": index, "_id": doc_id}}))
        lines.append(json.dumps(source))
    status, body = _signed_request(ctx, "POST", f"{base}/_bulk?refresh=true",
                                   raw="\n".join(lines) + "\n",
                                   content_type="application/x-ndjson")
    assert status == 200, f"_bulk returned HTTP {status!r}, expected 200: {body!r}"
    assert body.get("errors") is False, (
        f"_bulk reported per-item errors loading {index!r}: "
        f"{[i for i in body.get('items', []) if 'error' in i.get('index', {})]!r}")


def _drain(ctx, queue_url: str, *, deadline_s: float):
    """Receive the first message at the consumer within a bounded window, or return None.

    Long-polls, and deletes what it takes so the absence leg starts from an empty queue.
    """
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + deadline_s
    while time.monotonic() < deadline:
        received = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5,
            MessageAttributeNames=["All"])
        messages = received.get("Messages") or []
        if messages:
            for message in messages:
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"])
            return messages
    return None


def _visible_count(ctx, queue_url: str) -> int:
    attrs = ctx.client("sqs").get_queue_attributes(
        QueueUrl=queue_url,
        AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"])[
            "Attributes"]
    return int(attrs["ApproximateNumberOfMessages"]) + int(
        attrs["ApproximateNumberOfMessagesNotVisible"])


_SCENARIO = "alerting-sns-delivery"
_MARKER = "sim2real-behav-osalert"
_DOCS = [(f"a{i}", {"group": "a", "n": i}) for i in range(6)]


def _execute_monitor(ctx, base: str, monitor_id: str) -> dict:
    status, body = _signed_request(
        ctx, "POST", f"{base}/_plugins/_alerting/monitors/{monitor_id}/_execute")
    assert status == 200, (
        f"_execute of monitor {monitor_id!r} returned HTTP {status!r}, expected 200: {body!r}")
    return body


def _triggered(execution: dict) -> bool:
    """The single trigger's verdict. Hard-subscripted: an empty trigger_results is a failure."""
    results = execution["trigger_results"]
    assert len(results) == 1, (
        f"the execution reports {len(results)!r} trigger results, expected exactly 1: {execution!r}")
    only = next(iter(results.values()))
    return bool(only["triggered"])


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:eventing",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An alerting monitor whose trigger fires publishes the rendered document count via an SNS
    channel to SQS, withholds it once the index is emptied, and resumes with the new count.

    Reference: https://docs.aws.amazon.com/opensearch-service/latest/developerguide/alerting.html
    """
    topic_arn, queue_url = _sns_to_sqs(ctx, _SCENARIO)
    role_arn = _publish_role(ctx, _SCENARIO, topic_arn)

    domain = _create_min_domain(ctx, scenario=_SCENARIO)
    base = ctx.endpoint_url(_wait_searchable(ctx, domain))
    _wait_data_plane_ready(ctx, base)

    index = "sim2real-behav-alerting"
    status, created = _signed_request(ctx, "PUT", f"{base}/{index}", body={
        "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
        "mappings": {"properties": {"group": {"type": "keyword"}, "n": {"type": "integer"}}}})
    assert status == 200, f"creating index {index!r} returned HTTP {status!r}: {created!r}"
    ctx.on_cleanup(lambda: _signed_request(ctx, "DELETE", f"{base}/{index}"))
    _bulk_load(ctx, base, index, _DOCS)

    # The notification channel: OpenSearch's side of the SNS wiring.
    config_id = "sim2real-behav-osalert-chan"
    status, channel = _signed_request(
        ctx, "POST", f"{base}/_plugins/_notifications/configs",
        body={"config_id": config_id, "config": {
            "name": "sim2real behav alert channel",
            "description": "sim2real cross-service alerting delivery",
            "config_type": "sns",
            "is_enabled": True,
            "sns": {"topic_arn": topic_arn, "role_arn": role_arn}}})
    assert status in (200, 201), (
        f"creating the SNS notification channel returned HTTP {status!r}, expected 200/201: "
        f"{channel!r}")
    ctx.on_cleanup(
        lambda: _signed_request(ctx, "DELETE", f"{base}/_plugins/_notifications/configs/{config_id}"))
    status, fetched = _signed_request(
        ctx, "GET", f"{base}/_plugins/_notifications/configs/{config_id}")
    assert status == 200, f"GET of the notification channel returned HTTP {status!r}: {fetched!r}"
    assert json.dumps(fetched).count(topic_arn) >= 1, (
        f"the stored notification channel does not carry the topic ARN {topic_arn!r} it was created "
        f"with: {fetched!r}")

    # The monitor. Disabled, so only the explicit executions below can deliver anything.
    status, monitor = _signed_request(ctx, "POST", f"{base}/_plugins/_alerting/monitors", body={
        "type": "monitor",
        "name": "sim2real-behav-osalert-monitor",
        "monitor_type": "query_level_monitor",
        "enabled": False,
        "schedule": {"period": {"interval": 1, "unit": "MINUTES"}},
        "inputs": [{"search": {"indices": [index],
                               "query": {"size": 0, "query": {"term": {"group": "a"}}}}}],
        "triggers": [{"query_level_trigger": {
            "name": "sim2real-behav-osalert-trigger",
            "severity": "1",
            "condition": {"script": {"lang": "painless",
                                     "source": "ctx.results[0].hits.total.value > 0"}},
            "actions": [{
                "name": "sim2real-behav-osalert-action",
                "destination_id": config_id,
                "subject_template": {"lang": "mustache", "source": f"{_MARKER} subject"},
                "message_template": {
                    "lang": "mustache",
                    "source": _MARKER + " hits={{ctx.results.0.hits.total.value}}"}}]}}]})
    assert status in (200, 201), (
        f"creating the alerting monitor returned HTTP {status!r}, expected 200/201: {monitor!r}")
    monitor_id = monitor["_id"]
    ctx.on_cleanup(
        lambda: _signed_request(ctx, "DELETE", f"{base}/_plugins/_alerting/monitors/{monitor_id}"))

    # The queue must start empty, so the message asserted below is attributable to this execution.
    assert _visible_count(ctx, queue_url) == 0, (
        f"the freshly created queue already holds {_visible_count(ctx, queue_url)!r} messages")

    # POSITIVE LEG: the trigger fires and the message must arrive at the consumer.
    started = time.monotonic()
    execution = _execute_monitor(ctx, base, monitor_id)
    assert _triggered(execution) is True, (
        f"the trigger did not fire for an index holding {len(_DOCS)!r} matching documents; its "
        f"condition is `hits.total.value > 0`: {execution!r}")
    messages = _drain(ctx, queue_url, deadline_s=180.0)
    assert messages, (
        f"no SNS message reached the queue within 180s of a fired trigger -- the monitor's action "
        f"names the notification channel {config_id!r}, which names topic {topic_arn!r}")
    latency = time.monotonic() - started
    bodies = [m["Body"] for m in messages]
    assert len(bodies) == 1, (
        f"the queue received {len(bodies)!r} messages for one execution, expected exactly 1: "
        f"{bodies!r}")
    assert bodies[0] == f"{_MARKER} hits={len(_DOCS)}", (
        f"the delivered message body is {bodies[0]!r}, expected {_MARKER!r} followed by "
        f"'hits={len(_DOCS)}' -- the count is the value the engine computed for this run's documents "
        f"and rendered through the action's mustache template")

    # NEGATIVE LEG: remove the matching documents; the same monitor must now withhold delivery.
    status, deleted = _signed_request(
        ctx, "POST", f"{base}/{index}/_delete_by_query?refresh=true",
        body={"query": {"match_all": {}}})
    assert status == 200, f"_delete_by_query returned HTTP {status!r}: {deleted!r}"
    assert deleted.get("deleted") == len(_DOCS), (
        f"_delete_by_query removed {deleted.get('deleted')!r} documents, expected {len(_DOCS)!r}: "
        f"{deleted!r}")

    execution = _execute_monitor(ctx, base, monitor_id)
    assert _triggered(execution) is False, (
        f"the trigger fired for an emptied index; its condition is `hits.total.value > 0`: "
        f"{execution!r}")
    # The window is 3x the positive leg's latency, floored at 15s, so a slower target that would
    # still deliver is not graded as withholding.
    window = max(3.0 * latency, 15.0)
    stray = _drain(ctx, queue_url, deadline_s=window)
    assert stray is None, (
        f"a message arrived within {window:.0f}s of an execution whose trigger did NOT fire: "
        f"{[m['Body'] for m in stray] if stray else stray!r}")
    assert _visible_count(ctx, queue_url) == 0, (
        f"the queue reports {_visible_count(ctx, queue_url)!r} messages after a non-firing execution, "
        f"expected 0 -- a second observable of the same absence")

    # RESTORE: put one document back and delivery must resume, with the NEW count.
    _bulk_load(ctx, base, index, [("a0", {"group": "a", "n": 0})])
    execution = _execute_monitor(ctx, base, monitor_id)
    assert _triggered(execution) is True, (
        f"the trigger did not fire again after one matching document was re-indexed: {execution!r}")
    resumed = _drain(ctx, queue_url, deadline_s=max(180.0, 3.0 * latency))
    assert resumed, (
        "no message reached the queue after delivery was restored, so the withheld message above "
        "cannot be attributed to the trigger being false")
    assert [m["Body"] for m in resumed] == [f"{_MARKER} hits=1"], (
        f"the resumed delivery carried {[m['Body'] for m in resumed]!r}, expected exactly one body "
        f"reading {_MARKER!r} followed by 'hits=1'")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
