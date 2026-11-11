"""a-post-object-upload-is-withheld-from-a-putobject-scoped-rule."""

from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import json
import re
import time
import urllib.error
import urllib.request
import uuid

from behavioral_harness import tags

CHECK = "a-post-object-upload-is-withheld-from-a-putobject-scoped-rule"
GROUP = "event-propagation"
SERVICES = ["events", "s3", "sqs"]

_PREFIX = "nd-post/"
_MAX_BYTES = 65536
#: The worst-case wall clock of this check's sequential polls, so the suite is sized to fit them.
_WORST_CASE_BUDGET_S = 900


# ===== helpers =====
def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
    """A bounded retry that RAISES on its deadline; never returns its last value on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _make_queue(ctx, name, *, check_tag):
    """A queue any EventBridge rule in this account may send to."""
    sqs = ctx.client("sqs")
    account = ctx.client("sts").get_caller_identity()["Account"]
    url = sqs.create_queue(QueueName=name, tags={"sim2real-check": check_tag})["QueueUrl"]
    ctx.on_cleanup(lambda u=url: ctx.client("sqs").delete_queue(QueueUrl=u))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    sqs.set_queue_attributes(
        QueueUrl=url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "AllowEventBridge",
                            "Effect": "Allow",
                            "Principal": {"Service": "events.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": arn,
                            "Condition": {
                                "ArnLike": {
                                    "aws:SourceArn": (
                                        f"arn:*:events:{ctx.region}:{account}:rule/*"
                                    )
                                }
                            },
                        }
                    ],
                }
            )
        },
    )
    return url, arn


def _drain(ctx, url, *, seconds):
    """Receive and delete every message visible within `seconds`; return their parsed bodies."""
    sqs = ctx.client("sqs")
    out = []
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            out.append(json.loads(msg["Body"]))
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    return out


def _queue_depth(ctx, url):
    attrs = ctx.client("sqs").get_queue_attributes(
        QueueUrl=url,
        AttributeNames=[
            "ApproximateNumberOfMessages",
            "ApproximateNumberOfMessagesNotVisible",
            "ApproximateNumberOfMessagesDelayed",
        ],
    )["Attributes"]
    return sum(int(v) for v in attrs.values())


def _create_bucket(ctx, check_tag):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-nd-post-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":  # region-pinned API quirk, not a hardcoded region
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(ctx, name))
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={
            "TagSet": [
                {"Key": "sim2real:managed", "Value": "true"},
                {"Key": "sim2real-check", "Value": check_tag},
            ]
        },
    )
    return name


def _delete_bucket(ctx, name):
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=name):
        stale = [
            {"Key": o["Key"], "VersionId": o["VersionId"]}
            for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
        ]
        if stale:
            failed = s3.delete_objects(Bucket=name, Delete={"Objects": stale}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=name)


def _frozen_credentials(ctx):
    """ctx's own signing credentials, frozen. Nothing ambient is resolved."""
    creds = ctx.client("s3")._request_signer._credentials
    assert creds is not None, (
        "ctx.client('s3') carries no credentials, so no POST policy can be signed"
    )
    return creds.get_frozen_credentials()


def _bucket_post_url(ctx, bucket):
    """The POST Object target, derived FROM THE TARGET so it follows whichever addressing style the
    endpoint uses. Transport derivation only — no assertion forks on it."""
    probe = "post-object-endpoint-probe"
    presigned = ctx.client("s3").generate_presigned_url(
        "put_object", Params={"Bucket": bucket, "Key": probe}, ExpiresIn=60
    )
    base = presigned.split("?", 1)[0]
    assert base.endswith("/" + probe), (
        f"cannot derive the bucket URL: the presigned PutObject URL {base!r} does not end in /{probe}"
    )
    return base[: -len(probe)]


def _sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _signed_post_form(ctx, bucket):
    """A SigV4-signed POST Object policy, recomputed in pure Python from the LIVE clock and ctx's own
    credentials."""
    creds = _frozen_credentials(ctx)
    now = datetime.datetime.now(datetime.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")
    expiration = (now + datetime.timedelta(minutes=20)).strftime("%Y-%m-%dT%H:%M:%SZ")
    credential = f"{creds.access_key}/{datestamp}/{ctx.region}/s3/aws4_request"
    conditions = [
        {"bucket": bucket},
        ["starts-with", "$key", _PREFIX],
        {"x-amz-algorithm": "AWS4-HMAC-SHA256"},
        {"x-amz-credential": credential},
        {"x-amz-date": amz_date},
        {"success_action_status": "201"},
        ["content-length-range", 1, _MAX_BYTES],
    ]
    if creds.token:
        conditions.append({"x-amz-security-token": creds.token})
    policy = base64.b64encode(
        json.dumps({"expiration": expiration, "conditions": conditions}).encode("utf-8")
    ).decode("ascii")
    signing_key = _sign(
        _sign(_sign(_sign(f"AWS4{creds.secret_key}".encode("utf-8"), datestamp), ctx.region), "s3"),
        "aws4_request",
    )
    form = {
        "x-amz-algorithm": "AWS4-HMAC-SHA256",
        "x-amz-credential": credential,
        "x-amz-date": amz_date,
        "success_action_status": "201",
        "policy": policy,
        "x-amz-signature": hmac.new(
            signing_key, policy.encode("utf-8"), hashlib.sha256
        ).hexdigest(),
    }
    if creds.token:
        form["x-amz-security-token"] = creds.token
    return form


def _multipart_body(fields, *, key, payload, boundary):
    """A real browser-shaped multipart/form-data body. `key` must precede `file`, as POST Object
    ignores every field after `file`."""
    out = []
    for name, value in list(fields.items()) + [("key", key)]:
        out.append(f"--{boundary}\r\n".encode())
        out.append(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode())
        out.append(f"{value}\r\n".encode())
    out.append(f"--{boundary}\r\n".encode())
    out.append(
        b'Content-Disposition: form-data; name="file"; filename="upload.bin"\r\n'
        b"Content-Type: application/octet-stream\r\n\r\n"
    )
    out.append(payload)
    out.append(f"\r\n--{boundary}--\r\n".encode())
    return b"".join(out)


def _http_post(url, body, boundary):
    """Returns (status, body_bytes) for both success and HTTP error, so a 4xx is data rather than an
    exception that would need a broad except."""
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


#: A bucket created moments earlier can answer a POST with `307` and an `<Endpoint>` until its DNS
#: record reaches the Region (https://docs.aws.amazon.com/AmazonS3/latest/userguide/VirtualHosting.html);
#: the policy carries no Host assertion, so the SAME body is resubmitted, bounded by a redirect count.
_MAX_POST_REDIRECTS = 5
_ENDPOINT_RE = re.compile(rb"<Endpoint>([^<]+)</Endpoint>")


def _http_post_following_redirect(ctx, url, body, boundary):
    """`_http_post`, but a `307` naming a replacement `<Endpoint>` is followed, not treated as the
    answer. Raises if the chain does not settle within `_MAX_POST_REDIRECTS` hops."""
    chain = [url]
    for _ in range(_MAX_POST_REDIRECTS):
        status, response_body = _http_post(url, body, boundary)
        if status != 307:
            return status, response_body, chain
        match = _ENDPOINT_RE.search(response_body)
        assert match, (
            f"POST to {url} answered 307 with no <Endpoint> to follow: {response_body[:300]!r}"
        )
        url = f"{ctx.endpoint_url(match.group(1).decode())}/"
        chain.append(url)
    raise AssertionError(f"POST Object kept redirecting past {_MAX_POST_REDIRECTS} hops: {chain!r}")


def _put_targets_ok(events, rule, targets):
    resp = events.put_targets(Rule=rule, Targets=targets)
    assert resp.get("FailedEntryCount") == 0, (
        f"put_targets on {rule} reported failures, so the wiring under test does not exist: "
        f"{resp.get('FailedEntries')!r}"
    )


def _teardown_rule(ctx, rule):
    events = ctx.client("events")
    events.remove_targets(Rule=rule, Ids=["q"], Force=True)
    events.delete_rule(Name=rule, Force=True)


# ===== the check =====
@tags(
    "axis:negative-delivery",
    "cap:c1",
    "concern:data-plane",
    "concern:eventing",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A browser form-POST upload reaches the POST-Object-scoped rule only; the PutObject-scoped
    rule on the same bucket receives nothing even though the object was demonstrably created.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/EventBridge.html
    Reference: https://docs.aws.amazon.com/AmazonS3/latest/API/API_PostObject.html
    """
    s3 = ctx.client("s3")
    events = ctx.client("events")
    check_tag = CHECK
    suffix = uuid.uuid4().hex[:10]

    bucket = _create_bucket(ctx, check_tag)
    s3.put_bucket_notification_configuration(
        Bucket=bucket, NotificationConfiguration={"EventBridgeConfiguration": {}}
    )
    stored = s3.get_bucket_notification_configuration(Bucket=bucket)
    assert "EventBridgeConfiguration" in stored, (
        f"the bucket {bucket} does not report an EventBridgeConfiguration after it was set "
        f"({sorted(stored)!r}) — no event of either kind would be emitted and both legs below would "
        f"be vacuous"
    )

    put_url, put_arn = _make_queue(ctx, f"sim2real-nd-post-put-{suffix}", check_tag=check_tag)
    post_url, post_arn = _make_queue(ctx, f"sim2real-nd-post-post-{suffix}", check_tag=check_tag)

    def _rule(name_prefix, reason, queue_arn):
        name = ctx.unique_name(name_prefix)
        events.put_rule(
            Name=name,
            EventPattern=json.dumps(
                {
                    "source": ["aws.s3"],
                    "detail-type": ["Object Created"],
                    "detail": {"bucket": {"name": [bucket]}, "reason": [reason]},
                }
            ),
            State="ENABLED",
            Tags=[{"Key": "sim2real-check", "Value": check_tag}],
        )
        ctx.on_cleanup(lambda n=name: _teardown_rule(ctx, n))
        _put_targets_ok(events, name, [{"Id": "q", "Arn": queue_arn}])
        return name

    put_rule = _rule("sim2real-nd-post-putrule-", "PutObject", put_arn)
    post_rule = _rule("sim2real-nd-post-postrule-", "POST Object", post_arn)

    # BEAT 1 — the PutObject-scoped rule is proven live on this exact bucket, and L is measured.
    put_key = f"{_PREFIX}via-put-{suffix}.bin"
    t0 = time.monotonic()
    s3.put_object(Bucket=bucket, Key=put_key, Body=b"x" * 1024)
    put_events_seen = _poll_until(
        lambda: _drain(ctx, put_url, seconds=6),
        lambda msgs: any(m["detail"]["object"]["key"] == put_key for m in msgs),
        timeout_s=180,
        interval_s=0,
        description=(
            f"the PutObject-scoped rule {put_rule} delivered the event for {put_key!r} — the positive "
            f"control that makes the absence below evidence rather than an artefact"
        ),
    )
    latency = max(time.monotonic() - t0, 1.0)
    put_event = next(m for m in put_events_seen if m["detail"]["object"]["key"] == put_key)
    assert put_event["detail"]["reason"] == "PutObject", (
        f"the PutObject-scoped rule delivered an event whose reason is "
        f"{put_event['detail']['reason']!r}, expected 'PutObject' — if the reason does not match the "
        f"pattern the rule matched on something else and the disjointness claim is unfounded"
    )
    # The POST-scoped rule must not have matched the PutObject creation either. Same disjointness,
    # checked in the other direction.
    stray = _drain(ctx, post_url, seconds=max(latency, 10.0))
    assert stray == [], (
        f"the POST-Object-scoped rule {post_rule} received {len(stray)} event(s) for a plain "
        f"put_object: {[m['detail']['reason'] for m in stray]!r} — its pattern names reason "
        f"'POST Object' only"
    )

    # BEAT 2 — the subject: a real signed browser form POST over HTTPS to the bucket endpoint.
    post_key = f"{_PREFIX}via-post-{suffix}.bin"
    payload = uuid.uuid4().hex.encode() * 16
    boundary = f"sim2real{uuid.uuid4().hex}"
    form = _signed_post_form(ctx, bucket)
    status, response_body, redirect_chain = _http_post_following_redirect(
        ctx,
        _bucket_post_url(ctx, bucket),
        _multipart_body(form, key=post_key, payload=payload, boundary=boundary),
        boundary,
    )
    assert status == 201, (
        f"the signed POST Object upload of {post_key!r} answered HTTP {status} after following "
        f"{len(redirect_chain) - 1} redirect(s) {redirect_chain!r}, expected 201 "
        f"(success_action_status=201). Body: {response_body[:300]!r} — a failed upload would explain "
        f"the PutObject queue's emptiness without the reason filter doing anything"
    )
    head = s3.head_object(Bucket=bucket, Key=post_key)
    assert head["ContentLength"] == len(payload), (
        f"head_object reports ContentLength={head['ContentLength']} for {post_key!r}, expected "
        f"{len(payload)} — the object created by the form POST is the SECOND independent observable "
        f"that the creation really happened"
    )

    # The POST-scoped rule receives it, with the documented reason literal.
    post_msgs = _poll_until(
        lambda: _drain(ctx, post_url, seconds=6),
        lambda msgs: any(m["detail"]["object"]["key"] == post_key for m in msgs),
        timeout_s=180,
        interval_s=0,
        description=(
            f"the POST-Object-scoped rule {post_rule} delivered the event for the form upload "
            f"{post_key!r}"
        ),
    )
    post_event = next(m for m in post_msgs if m["detail"]["object"]["key"] == post_key)
    assert post_event["detail"]["reason"] == "POST Object", (
        f"the form upload's Object Created event carries reason="
        f"{post_event['detail']['reason']!r}, expected 'POST Object'. A target that reports every "
        f"creation as 'PutObject' would have delivered this event to {put_rule} instead"
    )
    assert post_event["detail"]["bucket"]["name"] == bucket, (
        f"the event names bucket {post_event['detail']['bucket']['name']!r}, expected {bucket!r}"
    )

    # BEAT 3 — THE NEGATIVE, held for 3x the measured latency and confirmed by queue depth.
    hold = max(3 * latency, 15.0)
    leaked = _drain(ctx, put_url, seconds=hold)
    assert leaked == [], (
        f"the PutObject-scoped rule {put_rule} received {len(leaked)} event(s) during a {hold:.0f}s "
        f"hold (3x the {latency:.0f}s measured S3->EventBridge->SQS latency) for an object created by "
        f"a form POST: {[(m['detail']['reason'], m['detail']['object']['key']) for m in leaked]!r}"
    )
    assert _queue_depth(ctx, put_url) == 0, (
        f"the PutObject queue reports depth {_queue_depth(ctx, put_url)} behind an empty receive — "
        f"the second independent observable disagrees with the first"
    )

    # BEAT 4 — the withheld path is not broken, only unmatched: a second put_object on the same
    # bucket still reaches the PutObject rule, so the emptiness above was a filter decision.
    encore_key = f"{_PREFIX}via-put-again-{suffix}.bin"
    s3.put_object(Bucket=bucket, Key=encore_key, Body=b"y" * 512)
    encore = _poll_until(
        lambda: _drain(ctx, put_url, seconds=6),
        lambda msgs: any(m["detail"]["object"]["key"] == encore_key for m in msgs),
        timeout_s=180,
        interval_s=0,
        description=(
            f"the PutObject-scoped rule {put_rule} is still live AFTER the withheld form upload — "
            f"the emptiness above is a reason mismatch, not a dead delivery path"
        ),
    )
    keys = sorted(m["detail"]["object"]["key"] for m in encore)
    assert keys == [encore_key], (
        f"the PutObject queue carried {keys!r} on the final leg, expected exactly [{encore_key!r}] — "
        f"the form upload's event must not arrive late"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
