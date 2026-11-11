"""aws-proxy-subtype-sqs-sendmessage-delivers-to-the-queue."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

from botocore.exceptions import ClientError

from behavioral_harness import tags

# The client receives SQS's query-protocol XML SendMessageResponse verbatim, so the MessageId is
# parsed from XML; a body that cannot satisfy MessageBody gets the gateway's own 400
# `{"message": "Bad Request"}`, and only the mapped `$request.body.msg` bytes reach the queue.

CHECK = "aws-proxy-subtype-sqs-sendmessage-delivers-to-the-queue"

GROUP = "integrations"

SERVICES = ["apigatewayv2", "sqs"]


@tags(
    "axis:happy-path",
    "cap:c7",
    "concern:data-plane",
    "concern:eventing",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """An HTTP API route with the ``SQS-SendMessage`` integration subtype enqueues the mapped ``MessageBody`` bytes with
    the MessageId the client received, and a body that cannot satisfy ``MessageBody`` is refused with nothing
    enqueued, after which the original request enqueues again."""
    marker = ctx.unique_name("sim2real-xsvc-sqsmsg-")
    sqs = ctx.client("sqs")
    queue_url = sqs.create_queue(
        QueueName=_xname(ctx, "subtypeq"), tags=_xsvc_resource_tags()
    )["QueueUrl"]
    ctx.on_cleanup(lambda: ctx.client("sqs").delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    # The gateway itself needs the permission — there is no Lambda in this check to hold it.
    credentials_arn = _create_role(
        ctx,
        "apigateway.amazonaws.com",
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": queue_arn}
            ],
        },
    )

    agw = ctx.client("apigatewayv2")
    api = agw.create_api(
        Name=_xname(ctx, "httpapi-sqssubtype"), ProtocolType="HTTP", Tags=_xsvc_resource_tags()
    )
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=api_id))
    integration_id = agw.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationSubtype="SQS-SendMessage",
        PayloadFormatVersion="1.0",
        CredentialsArn=credentials_arn,
        RequestParameters={"QueueUrl": queue_url, "MessageBody": "$request.body.msg"},
    )["IntegrationId"]
    agw.create_route(
        ApiId=api_id, RouteKey="POST /send", Target=f"integrations/{integration_id}"
    )
    agw.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True)
    ctx.on_cleanup(
        lambda: ctx.client("apigatewayv2").delete_stage(ApiId=api_id, StageName="$default")
    )

    stored = agw.get_integration(ApiId=api_id, IntegrationId=integration_id)
    assert stored.get("IntegrationSubtype") == "SQS-SendMessage", (
        f"the integration must be stored as the SQS-SendMessage subtype, GetIntegration reports "
        f"{stored.get('IntegrationSubtype')!r}"
    )
    assert (stored.get("RequestParameters") or {}).get("MessageBody") == "$request.body.msg", (
        f"the MessageBody mapping must be stored as authored, got "
        f"{(stored.get('RequestParameters') or {}).get('MessageBody')!r}"
    )

    url = f"{ctx.stage_url(api['ApiEndpoint'], '$default')}/send"
    _drain_queue(sqs, queue_url)

    # Beat 1 — the positive leg, and the calibration for the absence window below.
    started = time.monotonic()
    status, _, text = _poll_http(
        url,
        method="POST",
        body=json.dumps({"msg": marker}).encode(),
        headers={"Content-Type": "application/json"},
        accept=lambda s: s == 200,
        description="POST /send reaching the SQS-SendMessage integration",
    )
    assert status == 200, (
        f"expected 200 from the SQS-SendMessage subtype integration, got {status}: {text[:300]!r}"
    )
    delivered = _poll_until(
        lambda: _drain_queue(sqs, queue_url),
        lambda msgs: bool(msgs),
        timeout_s=60.0,
        interval_s=2.0,
        description=f"the mapped message arriving on {queue_url}",
    )
    enqueue_latency_s = max(time.monotonic() - started, 1.0)
    assert len(delivered) == 1, (
        f"one request must produce exactly one queue message, got {len(delivered)}: "
        f"{[m['Body'][:60] for m in delivered]!r}"
    )
    assert delivered[0]["Body"] == marker, (
        f"the queue message body must be exactly the mapped $request.body.msg value {marker!r}, "
        f"got {delivered[0]['Body']!r} — a target that forwards the whole request body sends "
        f"{json.dumps({'msg': marker})!r} instead"
    )
    response_message_id = _extract_sqs_message_id(text)
    assert response_message_id == delivered[0]["MessageId"], (
        f"the MessageId the client received must be the MessageId the consumer reads off the "
        f"queue: response {response_message_id!r} vs queue {delivered[0]['MessageId']!r} "
        f"(response body was {text[:200]!r})"
    )

    # Beat 2/3 — a request that cannot satisfy the REQUIRED MessageBody parameter: refused, and
    # nothing enqueued for a window scaled to the measured enqueue latency.
    bad_status, _, bad_text = _http(
        "POST",
        url,
        body=json.dumps({"not-msg": marker}).encode(),
        headers={"Content-Type": "application/json"},
    )
    assert bad_status == 400, (
        f"a request whose body cannot satisfy the required MessageBody parameter must be refused "
        f"with 400 (the gateway's own parameter-mapping error, not a passthrough from SQS), got "
        f"{bad_status}: {bad_text[:300]!r}"
    )
    assert json.loads(bad_text).get("message") == "Bad Request", (
        f"the 400 must carry the gateway's own {{'message': 'Bad Request'}} body, not an SQS "
        f"passthrough or a different error shape, got {bad_text[:300]!r}"
    )
    _assert_nothing_enqueued(
        sqs,
        queue_url,
        window_s=min(max(3.0 * enqueue_latency_s, 15.0), 45.0),
        latency_s=enqueue_latency_s,
        because="a request refused for an unresolvable required parameter must enqueue nothing",
    )

    # Beat 4 — restore: the identical original request enqueues again.
    status, _, text = _http(
        "POST",
        url,
        body=json.dumps({"msg": f"{marker}-again"}).encode(),
        headers={"Content-Type": "application/json"},
    )
    assert status == 200, (
        f"the well-formed request must still be accepted after the refusal, got {status}: "
        f"{text[:300]!r}"
    )
    again = _poll_until(
        lambda: _drain_queue(sqs, queue_url),
        lambda msgs: bool(msgs),
        timeout_s=60.0,
        interval_s=2.0,
        description="the second mapped message arriving on the queue",
    )
    assert [m["Body"] for m in again] == [f"{marker}-again"], (
        f"expected exactly the second mapped body ['{marker}-again'] on the queue, got "
        f"{[m['Body'] for m in again]!r}"
    )




_XSVC_PREFIX = "sim2real-xsvc-"


def _xsvc_resource_tags() -> dict:
    return {"sim2real:managed": "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


_SQS_QUERY_XMLNS = "http://queue.amazonaws.com/doc/2012-11-05/"


def _extract_sqs_message_id(text: str) -> str | None:
    """The AWS_PROXY-to-SQS response is SQS's own classic query-protocol XML
    (``SendMessageResponse``/``SendMessageResult``/``MessageId``), passed through verbatim — not the
    JSON the gateway's own error format uses. A target that translates it to JSON, or drops it, fails
    the join in the caller rather than here."""
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None
    el = root.find(f".//{{{_SQS_QUERY_XMLNS}}}MessageId")
    return el.text if el is not None else None


def _drain_queue(sqs, queue_url):
    """Receive-and-delete every visible message; return them. The list IS the assertion."""
    out = []
    for _ in range(5):
        messages = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=1
        ).get("Messages", [])
        if not messages:
            break
        for msg in messages:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        out.extend(messages)
    return out


def _assert_nothing_enqueued(sqs, queue_url, *, window_s, latency_s, because):
    """Hold "no message" for a window calibrated to the measured enqueue latency, sampling
    repeatedly, and confirm with the queue's own reported depth as a second observable."""
    deadline = time.monotonic() + window_s
    samples = 0
    while True:
        arrived = _drain_queue(sqs, queue_url)
        assert not arrived, (
            f"{because}: {len(arrived)} message(s) arrived within the {window_s:.1f}s window "
            f"(calibrated from a measured enqueue latency of {latency_s:.2f}s): "
            f"{[m['Body'][:60] for m in arrived]!r}"
        )
        samples += 1
        if time.monotonic() >= deadline:
            break
        time.sleep(min(3.0, max(0.5, deadline - time.monotonic())))
    assert samples >= 2, (
        f"the absence window took {samples} sample(s), too few to be meaningful; expected >= 2 "
        f"over {window_s:.1f}s"
    )
    depth = int(
        sqs.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=["ApproximateNumberOfMessages"]
        )["Attributes"]["ApproximateNumberOfMessages"]
    )
    assert depth == 0, (
        f"{because}: the queue reports ApproximateNumberOfMessages == {depth}, expected 0"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result); return it. RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
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


def _poll_http(
    url,
    *,
    accept,
    method="GET",
    body=None,
    headers=None,
    timeout_s=180.0,
    interval_s=5.0,
    description="invoke URL",
):
    """Poll an invoke URL until accept(status); return (status, headers, text). RAISES on timeout.

    This also absorbs IAM propagation: a brand-new CredentialsArn is not immediately usable by
    API Gateway, which surfaces as a 5xx on the first requests.
    """
    deadline = time.monotonic() + timeout_s
    last = (None, [], "")
    while True:
        try:
            last = _http(method, url, body=body, headers=headers, timeout_s=20)
        except OSError as exc:  # execute-api DNS/TLS still settling
            last = (None, [], f"connection error: {exc}")
        else:
            if accept(last[0]):
                return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} ({url}) never reached an accepted status within {timeout_s}s. "
        f"Last: {last[0]} {last[2][:300]!r}"
    )


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
