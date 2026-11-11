"""raw-message-delivery-drops-message-attributes-for-an-https-subscriber-but-keeps-them-for-sqs."""
from __future__ import annotations

import base64
import io
import json
import time
import urllib.parse
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = (
    "raw-message-delivery-drops-message-attributes-for-an-https-subscriber-but-keeps-them-for-sqs"
)
GROUP = "delivery-format"
SERVICES = ["sns"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:eventing",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """With raw delivery, one Publish's String and Number attributes reach the SQS subscriber as
    SQS MessageAttributes, but the HTTPS subscriber's POST carries none of them: its body, header
    names and x-amz-sns-* values (bar message id) match a publish with zero attributes."""
    sns = ctx.client("sns")
    topic = sns.create_topic(Name=ctx.unique_name("sim2real-behav-sns-rawattr-"),
                             Tags=[{"Key": "sim2real", "Value": CHECK}])["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic))

    sqs_url, sqs_arn = _create_queue_for_topic(ctx, topic)
    _subscribe_sqs_and_confirm(ctx, topic, sqs_arn, attributes={"RawMessageDelivery": "true"})

    endpoint, capture_url, fn = _https_endpoint(ctx, [topic])
    https_sub, conf = _subscribe_https_and_capture_confirmation(ctx, topic, endpoint, capture_url)
    sns.confirm_subscription(TopicArn=topic, Token=conf["Token"])
    _bind_raw_subscription(ctx, fn, topic, https_sub)
    sns.set_subscription_attributes(SubscriptionArn=https_sub, AttributeName="RawMessageDelivery",
                                    AttributeValue="true")

    body = ctx.unique_name("sim2real-rawattr-body-")
    mid = sns.publish(TopicArn=topic, Message=body, MessageAttributes={
        "color": {"DataType": "String", "StringValue": "red"},
        "count": {"DataType": "Number", "StringValue": "42"},
    })["MessageId"]

    sqs = ctx.client("sqs")
    sqs_msg = _receive_by_body(sqs, sqs_url, body, timeout_s=90.0)
    sqs_attrs = sqs_msg["MessageAttributes"]
    assert sqs_attrs["color"]["StringValue"] == "red" and sqs_attrs["color"]["DataType"] == "String", (
        f"the SQS raw subscriber must receive the String attribute verbatim, got {sqs_attrs.get('color')!r}")
    assert sqs_attrs["count"]["StringValue"] == "42" and sqs_attrs["count"]["DataType"] == "Number", (
        f"the SQS raw subscriber must receive the Number attribute verbatim, got {sqs_attrs.get('count')!r}")
    assert sqs_msg["Body"] == body, f"the SQS raw body must be the published body itself, got {sqs_msg['Body']!r}"

    got = _capture_for(ctx, capture_url, mid)
    assert got["body"] == body, (
        f"the HTTPS raw body must be the published body itself, with no attribute data folded "
        f"in; got {got['body']!r}")
    sns_headers = {k: v for k, v in got["headers"].items() if k.startswith("x-amz-sns-")}
    assert sns_headers == {
        "x-amz-sns-message-type": "Notification", "x-amz-sns-topic-arn": topic,
        "x-amz-sns-message-id": mid, "x-amz-sns-subscription-arn": https_sub,
        "x-amz-sns-rawdelivery": "true",
    }, f"the HTTPS raw subscriber's x-amz-sns-* header set is {sns_headers!r}"
    carriers = {k: v for k, v in got["headers"].items()
                if any(t in k for t in ("color", "count")) or v in ("red", "42") or "color" in v}
    assert carriers == {}, (
        f"no header of the HTTPS raw POST may carry an attribute name or value; got {carriers!r} "
        f"among {sorted(got['headers'])!r}")

    # Comparison publish with zero attributes: the same header NAMES, and the same x-amz-sns-*
    # values apart from the message id -- the attributes changed nothing about the POST.
    plain_body = ctx.unique_name("sim2real-rawattr-plain-")
    plain_mid = sns.publish(TopicArn=topic, Message=plain_body)["MessageId"]
    plain = _capture_for(ctx, capture_url, plain_mid)
    assert plain["body"] == plain_body, f"the zero-attribute raw body is {plain['body']!r}"
    assert sorted(plain["headers"]) == sorted(got["headers"]), (
        f"the attribute-carrying POST's header names {sorted(got['headers'])!r} differ from the "
        f"zero-attribute POST's {sorted(plain['headers'])!r}")
    plain_sns = {k: v for k, v in plain["headers"].items() if k.startswith("x-amz-sns-")}
    assert {**plain_sns, "x-amz-sns-message-id": mid} == sns_headers, (
        f"the zero-attribute POST's x-amz-sns-* headers {plain_sns!r} differ from the "
        f"attribute-carrying POST's {sns_headers!r} beyond the message id")


def _capture_for(ctx, capture_url: str, message_id: str) -> dict:
    recs = _captured(ctx, capture_url,
                     lambda r: any(x["headers"].get("x-amz-sns-message-id") == message_id for x in r))
    matching = [x for x in recs if x["headers"].get("x-amz-sns-message-id") == message_id]
    assert matching, f"the HTTPS endpoint never received message {message_id!r}; captured {recs!r}"
    return matching[0]


def _create_queue_for_topic(ctx, topic_arn: str) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-sns-rawattr-q-")
    url = sqs.create_queue(QueueName=name, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda u=url: _delete_queue_if_present(ctx, u))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}}}],
    }
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    return url, arn

def _delete_queue_if_present(ctx, url: str) -> None:
    try:
        ctx.client("sqs").delete_queue(QueueUrl=url)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "AWS.SimpleQueueService.NonExistentQueue":
            raise

def _subscribe_sqs_and_confirm(ctx, topic_arn: str, queue_arn: str, *, attributes: dict,
                               timeout_s: float = 60.0) -> str:
    sns = ctx.client("sns")
    sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn,
                            ReturnSubscriptionArn=True, Attributes=attributes)["SubscriptionArn"]
    ctx.on_cleanup(lambda s=sub_arn: ctx.client("sns").unsubscribe(SubscriptionArn=s))
    deadline = time.monotonic() + timeout_s
    while sns.get_subscription_attributes(SubscriptionArn=sub_arn)["Attributes"].get(
            "PendingConfirmation") != "false":
        if time.monotonic() >= deadline:
            raise AssertionError("the sqs subscription never left PendingConfirmation")
        time.sleep(1.0)
    return sub_arn

def _receive_by_body(sqs, queue_url: str, body: str, *, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5,
                                   MessageAttributeNames=["All"], AttributeNames=["All"])
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if msg["Body"] == body:
                return msg
    raise AssertionError(f"message with body {body!r} never arrived within {timeout_s}s")


# The HTTPS endpoint is a Lambda function URL that admits only messages whose SNS signature
# verifies against a certificate on the SNS host of the check's own client; a raw delivery, which
# SNS does not sign, must carry the subscription and topic ARNs the check binds. Anything else
# gets 403. It copies each admitted request's headers (all of them, names lower-cased) and body
# into a capture queue.

_HANDLER = r'''
import base64, hashlib, hmac, json, os, re, urllib.parse, urllib.request, boto3
_sqs = boto3.client("sqs")
# The keys SNS signs for each message type, in signing order.
_SIGNED = {
    "Notification": ("Message", "MessageId", "Subject", "Timestamp", "TopicArn", "Type"),
    "SubscriptionConfirmation": (
        "Message", "MessageId", "SubscribeURL", "Timestamp", "Token", "TopicArn", "Type"),
    "UnsubscribeConfirmation": (
        "Message", "MessageId", "SubscribeURL", "Timestamp", "Token", "TopicArn", "Type"),
}
# RSASSA-PKCS1-v1_5 DigestInfo prefix per SignatureVersion: 1 signs with SHA-1, 2 with SHA-256.
_DIGESTS = {
    "1": (hashlib.sha1, bytes.fromhex("3021300906052b0e03021a05000414")),
    "2": (hashlib.sha256, bytes.fromhex("3031300d060960864801650304020105000420")),
}
_RSA_OID = bytes.fromhex("2a864886f70d010101")
_CERT_PATH = re.compile(r"/SimpleNotificationService-[0-9a-f]+\.pem")
_KEYS = {}
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # a redirect is an HTTPError, so the certificate comes only from the pinned URL
_OPENER = urllib.request.build_opener(_NoRedirect)
def _tlv(buf, i, tag):
    if i + 2 > len(buf) or buf[i] != tag:
        raise ValueError("unexpected DER")
    n, i = buf[i + 1], i + 2
    if n & 0x80:
        k = n & 0x7F
        n, i = int.from_bytes(buf[i:i + k], "big"), i + k
    if i + n > len(buf):
        raise ValueError("truncated DER")
    return buf[i:i + n], i + n
def _rsa_key(pem):
    """(modulus, exponent) of the RSA SubjectPublicKeyInfo of a PEM X.509 certificate."""
    der = base64.b64decode("".join(x for x in pem.splitlines() if x and not x.startswith("-----")))
    cert, _ = _tlv(der, 0, 0x30)
    tbs, _ = _tlv(cert, 0, 0x30)
    i = _tlv(tbs, 0, 0xA0)[1] if tbs[:1] == b"\xa0" else 0
    for _ in range(5):  # serialNumber, signature, issuer, validity, subject
        i = _tlv(tbs, i, tbs[i] if i < len(tbs) else -1)[1]
    spki, _ = _tlv(tbs, i, 0x30)
    alg, j = _tlv(spki, 0, 0x30)
    oid, _ = _tlv(alg, 0, 0x06)
    bits, _ = _tlv(spki, j, 0x03)
    if oid != _RSA_OID or bits[:1] != b"\x00":
        raise ValueError("not an RSA key")
    key, _ = _tlv(bits, 1, 0x30)
    n, j = _tlv(key, 0, 0x02)
    e, _ = _tlv(key, j, 0x02)
    return int.from_bytes(n, "big"), int.from_bytes(e, "big")
def _signed_by_sns(msg):
    """An RSA signature (SignatureVersion 1 or 2) over SNS's canonical string, verified with the
    certificate at an https SigningCertURL on exactly the SNS host the check pinned."""
    kind, version = msg.get("Type"), msg.get("SignatureVersion")
    cert_url = str(msg.get("SigningCertURL", ""))
    url = urllib.parse.urlsplit(cert_url)
    if (kind not in _SIGNED or version not in _DIGESTS
            or msg.get("TopicArn") not in os.environ["TOPIC_ARNS"].split(",")
            or url.scheme != "https" or url.username is not None or url.password is not None
            or url.hostname != os.environ["SNS_CERT_HOST"] or url.port not in (None, 443)
            or url.query or url.fragment or not _CERT_PATH.fullmatch(url.path)):
        return False
    if cert_url not in _KEYS:
        try:
            with _OPENER.open(cert_url, timeout=5) as resp:
                if resp.status != 200:
                    return False
                _KEYS[cert_url] = _rsa_key(resp.read().decode("ascii"))
        except OSError:  # URLError, HTTPError (incl. refused redirects), timeouts
            return False
    n, e = _KEYS[cert_url]
    hasher, prefix = _DIGESTS[version]
    signed = "".join("%s\n%s\n" % (k, msg[k]) for k in _SIGNED[kind] if k in msg)
    sig = base64.b64decode(str(msg.get("Signature", "")), validate=True)
    size = (n.bit_length() + 7) // 8
    digest = hasher(signed.encode("utf-8")).digest()
    pad = size - len(prefix) - len(digest) - 3
    want = b"\x00\x01" + b"\xff" * pad + b"\x00" + prefix + digest
    value = int.from_bytes(sig, "big")
    return pad >= 8 and len(sig) == size and value < n and pow(value, e, n).to_bytes(size, "big") == want
def _raw_admitted(hdrs):
    """SNS signs no raw delivery: admitted only as a Notification of the exact subscription and
    topic the check bound into the environment before it enabled raw delivery."""
    want = os.environ.get("RAW_SUBSCRIPTION_ARN", "")
    return (bool(want) and hdrs.get("x-amz-sns-message-type") == "Notification"
            and hdrs.get("x-amz-sns-topic-arn") == os.environ.get("RAW_TOPIC_ARN")
            and hmac.compare_digest(hdrs.get("x-amz-sns-subscription-arn", "").encode(), want.encode()))
def _authentic(hdrs, body):
    if hdrs.get("x-amz-sns-rawdelivery") == "true":
        return _raw_admitted(hdrs)
    try:
        msg = json.loads(body)
        return (isinstance(msg, dict) and msg.get("Type") == hdrs.get("x-amz-sns-message-type")
                and _signed_by_sns(msg))
    except ValueError:
        return False
def handler(event, context):
    hdrs = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    body = event.get("body") or ""
    if event.get("isBase64Encoded"):
        body = base64.b64decode(body).decode("utf-8")
    if not _authentic(hdrs, body):
        return {"statusCode": 403, "body": ""}
    _sqs.send_message(QueueUrl=os.environ["CAPTURE_URL"], MessageBody=json.dumps({
        "headers": hdrs, "body": body}))
    return {"statusCode": 200, "body": ""}
'''


def _bind_raw_subscription(ctx, fn: str, topic: str, sub: str) -> None:
    """Name the one subscription whose unsigned raw deliveries the handler admits."""
    lam = ctx.client("lambda")
    env = lam.get_function_configuration(FunctionName=fn)["Environment"]["Variables"]
    lam.update_function_configuration(FunctionName=fn, Environment={"Variables": {
        **env, "RAW_TOPIC_ARN": topic, "RAW_SUBSCRIPTION_ARN": sub}})
    lam.get_waiter("function_updated_v2").wait(FunctionName=fn, WaiterConfig={"Delay": 2, "MaxAttempts": 150})


def _zip_handler() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        info = zipfile.ZipInfo("index.py")
        info.external_attr = 0o644 << 16
        zf.writestr(info, _HANDLER)
    return buf.getvalue()


def _create_capture_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-sns-rawattr-cap-"),
                           tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _https_endpoint(ctx, topics: list[str]) -> tuple[str, str, str]:
    """(function URL to subscribe for ``topics``, capture queue URL, function name)."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    capture_url, capture_arn = _create_capture_queue(ctx)

    cert_host = urllib.parse.urlsplit(ctx.service_url(f"https://sns.{ctx.region}.amazonaws.com")).hostname
    fn = ctx.unique_name("sim2real-behav-sns-rawattr-fn-")

    role = ctx.unique_name("sim2real-behav-sns-rawattr-fn-")
    role_arn = iam.create_role(
        RoleName=role,
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole"}]}),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role))
    iam.put_role_policy(RoleName=role, PolicyName="capture", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": "sqs:SendMessage", "Resource": capture_arn}]}))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role, PolicyName="capture"))

    deadline = time.monotonic() + 90
    while True:
        try:
            lam.create_function(
                FunctionName=fn, Runtime="python3.12", Handler="index.handler", Role=role_arn,
                Code={"ZipFile": _zip_handler()}, Timeout=10,
                Environment={"Variables": {"CAPTURE_URL": capture_url, "SNS_CERT_HOST": cert_host,
                                           "TOPIC_ARNS": ",".join(topics)}},
                Tags={"sim2real": CHECK},
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn))
    lam.get_waiter("function_active_v2").wait(FunctionName=fn, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    url = lam.create_function_url_config(FunctionName=fn, AuthType="NONE")["FunctionUrl"]
    ctx.on_cleanup(lambda: lam.delete_function_url_config(FunctionName=fn))
    lam.add_permission(FunctionName=fn, StatementId="url", Action="lambda:InvokeFunctionUrl",
                       Principal="*", FunctionUrlAuthType="NONE")
    lam.add_permission(FunctionName=fn, StatementId="invoke", Action="lambda:InvokeFunction",
                       Principal="*", InvokedViaFunctionUrl=True)
    return url, capture_url, fn


def _captured(ctx, capture_url: str, want, timeout_s: float = 120.0) -> list[dict]:
    """Drain the capture queue until ``want(records)`` holds or the deadline passes. Each
    record is ``{"headers": {...}, "body": <raw string>}`` -- the body is left unparsed because
    a raw-delivery record's body is the published payload verbatim, not JSON."""
    sqs = ctx.client("sqs")
    out: list[dict] = []
    deadline = time.monotonic() + timeout_s
    while True:
        resp = sqs.receive_message(QueueUrl=capture_url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
        for msg in resp.get("Messages", []):
            rec = json.loads(msg["Body"])
            out.append(rec)
            sqs.delete_message(QueueUrl=capture_url, ReceiptHandle=msg["ReceiptHandle"])
        if want(out) or time.monotonic() >= deadline:
            return out


def _as_confirmation(rec: dict, topic_arn: str) -> dict | None:
    """The parsed SubscriptionConfirmation envelope for this topic, or None."""
    try:
        parsed = json.loads(rec["body"])
    except ValueError:
        return None
    if isinstance(parsed, dict) and parsed.get("Type") == "SubscriptionConfirmation" \
            and parsed.get("TopicArn") == topic_arn:
        return parsed
    return None


def _unsubscribe(ctx, sub: str) -> None:
    """Unsubscribe; a subscription still pending confirmation cannot be, and DeleteTopic removes it."""
    try:
        ctx.client("sns").unsubscribe(SubscriptionArn=sub)
    except ClientError as exc:
        err = exc.response["Error"]
        if err["Code"] != "InvalidParameter" or "pending confirmation" not in err.get("Message", ""):
            raise


def _subscribe_https_and_capture_confirmation(ctx, topic_arn: str, endpoint: str,
                                              capture_url: str) -> tuple[str, dict]:
    sns = ctx.client("sns")
    deadline = time.monotonic() + 240
    while True:
        sub = sns.subscribe(TopicArn=topic_arn, Protocol="https", Endpoint=endpoint,
                            ReturnSubscriptionArn=True)["SubscriptionArn"]
        ctx.on_cleanup(lambda s=sub: _unsubscribe(ctx, s))
        recs = _captured(ctx, capture_url,
                         lambda r: any(_as_confirmation(x, topic_arn) for x in r), timeout_s=45)
        confs = [c for x in recs if (c := _as_confirmation(x, topic_arn))]
        if confs:
            return sub, confs[0]
        assert time.monotonic() < deadline, (
            f"no SubscriptionConfirmation for the topic reached the HTTPS endpoint; captured {recs!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
