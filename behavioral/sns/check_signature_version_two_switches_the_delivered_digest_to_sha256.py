"""signature-version-two-switches-the-delivered-digest-to-sha256."""
from __future__ import annotations

import base64
import hashlib
import json
import time
import urllib.request
from urllib.parse import urlparse

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "signature-version-two-switches-the-delivered-digest-to-sha256"
GROUP = "server-side"
SERVICES = ["sns"]

_SCENARIO = "sns-sigv2"

# DigestInfo DER prefixes for RSASSA-PKCS1-v1_5, keyed by the SNS SignatureVersion that
# selects the digest: version 1 signs with SHA-1, version 2 with SHA-256.
_DIGESTS = {
    "1": (hashlib.sha1, bytes.fromhex("3021300906052b0e03021a05000414")),
    "2": (hashlib.sha256, bytes.fromhex("3031300d060960864801650304020105000420")),
}


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:eventing",
      "concern:negative-classes", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Setting topic SignatureVersion 2 makes delivered notifications verify under SHA-256 and not
    SHA-1, setting 1 reverses that, and SignatureVersion 3 is refused without changing the value.

    Reference: https://docs.aws.amazon.com/sns/latest/dg/sns-verify-signature-of-message.html
    """
    sns = ctx.client("sns")
    topic_arn = _create_topic(ctx)
    queue_url, queue_arn = _create_queue_for_topic(ctx, topic_arn)
    # NOT raw delivery: the Signature, SigningCertURL and SignatureVersion live in the JSON
    # notification envelope, which raw delivery strips.
    _subscribe_and_confirm(ctx, topic_arn, queue_arn)

    declared_default = sns.get_topic_attributes(
        TopicArn=topic_arn)["Attributes"].get("SignatureVersion", "1")
    assert declared_default == "1", (
        "a freshly created topic must declare SignatureVersion 1 (documented default); got "
        f"{declared_default!r} — every leg below is relative to this baseline"
    )

    _assert_signed_with(ctx, sns, topic_arn, queue_url, expect_version="1")

    _set_signature_version(ctx, sns, topic_arn, "2")
    _assert_signed_with(ctx, sns, topic_arn, queue_url, expect_version="2")

    _set_signature_version(ctx, sns, topic_arn, "1")
    _assert_signed_with(ctx, sns, topic_arn, queue_url, expect_version="1")

    code, message = _error(lambda: sns.set_topic_attributes(
        TopicArn=topic_arn, AttributeName="SignatureVersion", AttributeValue="3"))
    assert code == "InvalidParameter", (
        "expected SetTopicAttributes(SignatureVersion=3) to be refused with Code "
        f"'InvalidParameter' — the documented value set is {{1, 2}}; got Code {code!r} and "
        f"Message {message!r}"
    )
    assert message == "Invalid parameter: SignatureVersion: Invalid value '[3]'. Must be 1 or 2.", (
        f"expected the exact message \"Invalid parameter: SignatureVersion: Invalid value '[3]'. Must be 1 or 2.\", got {message!r}"
    )
    after = sns.get_topic_attributes(
        TopicArn=topic_arn)["Attributes"].get("SignatureVersion")
    assert after == "1", (
        "a refused SetTopicAttributes must not change the stored SignatureVersion: expected "
        f"'1', got {after!r}"
    )




def _set_signature_version(ctx, sns, topic_arn: str, version: str) -> None:
    """Set the topic's SignatureVersion and poll an independent read until it reflects it."""
    sns.set_topic_attributes(
        TopicArn=topic_arn, AttributeName="SignatureVersion", AttributeValue=version)
    _poll_until(
        lambda: sns.get_topic_attributes(
            TopicArn=topic_arn)["Attributes"].get("SignatureVersion"),
        lambda value: value == version,
        timeout_s=60.0,
        interval_s=2.0,
        description=f"GetTopicAttributes reflects SignatureVersion={version}",
    )


def _assert_signed_with(ctx, sns, topic_arn: str, queue_url: str, *,
                        expect_version: str) -> None:
    """Publish, then require the delivered notification to verify under expect_version's
    digest and to fail under the other version's digest."""
    marker = ctx.unique_name(f"sim2real-behav-sns-sigv{expect_version}-")
    subject = f"sim2real-sigv{expect_version}"
    sns.publish(TopicArn=topic_arn, Subject=subject, Message=marker)
    envelope = _await_envelope(
        ctx, queue_url, marker, timeout_s=120.0,
        description=f"the notification published under SignatureVersion={expect_version}",
    )

    got_version = envelope["SignatureVersion"]
    assert got_version == expect_version, (
        f"expected the delivered envelope to report SignatureVersion {expect_version!r} "
        f"after the topic attribute was set to it; got {got_version!r}"
    )
    assert envelope["Subject"] == subject, (
        f"expected the Subject to survive delivery as {subject!r}, got "
        f"{envelope['Subject']!r} — the Subject is part of the signed canonical string"
    )

    cert_url = envelope["SigningCertURL"]
    parsed = urlparse(cert_url)
    assert parsed.scheme in ("http", "https"), f"SigningCertURL is not http(s): {cert_url!r}"
    assert parsed.hostname, f"SigningCertURL names no host: {cert_url!r}"
    # A raw HTTPS GET to the host the envelope itself named.
    target_url, route_headers = ctx.endpoint_route(cert_url)
    request = urllib.request.Request(target_url, headers=route_headers)
    with urllib.request.urlopen(request, timeout=30, context=_ssl_context(ctx.http_verify)) as resp:  # noqa: S310
        pem = resp.read().decode("utf-8")
    assert "BEGIN CERTIFICATE" in pem, (
        f"SigningCertURL did not serve a PEM certificate: {pem[:120]!r}"
    )
    modulus, exponent = _rsa_public_key_from_certificate(pem)

    canonical = _canonical_string(envelope).encode("utf-8")
    signature = base64.b64decode(envelope["Signature"])

    matching = _verify_pkcs1v15(canonical, signature, modulus, exponent, expect_version)
    assert matching is True, (
        f"the Signature on a notification delivered while SignatureVersion={expect_version} "
        f"must verify under {_DIGESTS[expect_version][0]().name.upper()}; RSASSA-PKCS1-v1_5 "
        f"verification failed over {len(canonical)} canonical bytes with a "
        f"{modulus.bit_length()}-bit key"
    )
    other = "1" if expect_version == "2" else "2"
    crossed = _verify_pkcs1v15(canonical, signature, modulus, exponent, other)
    assert crossed is False, (
        f"a notification signed under SignatureVersion={expect_version} must NOT verify under "
        f"version {other}'s digest ({_DIGESTS[other][0]().name.upper()}); it did, which means "
        "the digest is not actually selected by the attribute (or the verifier accepts "
        "anything)"
    )


def _await_envelope(ctx, queue_url: str, marker: str, *, timeout_s: float,
                    description: str) -> dict:
    """Long-poll until a notification envelope whose Message is exactly `marker` arrives; raise
    on the deadline."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    others: list[str] = []
    while True:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            envelope = json.loads(msg["Body"])
            if envelope.get("Message") == marker:
                return envelope
            others.append(str(envelope.get("Message"))[:60])
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: no envelope with Message == {marker!r} arrived within "
                f"{timeout_s}s; bodies seen: {others!r}"
            )


def _canonical_string(envelope: dict) -> str:
    """The string SNS signs for a Notification: field\\nvalue\\n per signed key, in the
    documented order."""
    order = ["Message", "MessageId", "Subject", "Timestamp", "TopicArn", "Type"]
    parts = []
    for key in order:
        if key == "Subject" and "Subject" not in envelope:
            continue
        parts.append(f"{key}\n{envelope[key]}\n")
    return "".join(parts)


def _der_tlv(buf: bytes, i: int) -> tuple[int, bytes, int]:
    """Read one DER tag-length-value at offset i; returns (tag, content, next_offset)."""
    tag = buf[i]
    i += 1
    length = buf[i]
    i += 1
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(buf[i:i + n], "big")
        i += n
    end = i + length
    if end > len(buf):
        raise ValueError("truncated DER")
    return tag, buf[i:end], end


def _rsa_public_key_from_certificate(pem: str) -> tuple[int, int]:
    """Extract (modulus, exponent) from an X.509 PEM certificate with no crypto library."""
    body = "".join(
        line for line in pem.splitlines() if line and not line.startswith("-----")
    )
    der = base64.b64decode(body)
    stack = [der]
    while stack:
        buf = stack.pop(0)
        i = 0
        while i < len(buf):
            try:
                tag, content, i = _der_tlv(buf, i)
            except (IndexError, ValueError):
                break
            if tag == 0x03 and content[:1] == b"\x00":
                try:
                    inner_tag, inner, _ = _der_tlv(content[1:], 0)
                    if inner_tag == 0x30:
                        t_n, c_n, j = _der_tlv(inner, 0)
                        t_e, c_e, _ = _der_tlv(inner, j)
                        if t_n == 0x02 and t_e == 0x02:
                            n = int.from_bytes(c_n, "big")
                            e = int.from_bytes(c_e, "big")
                            if 1024 <= n.bit_length() <= 8192 and 3 <= e <= 1 << 32:
                                return n, e
                except (IndexError, ValueError):
                    pass
            if tag & 0x20:
                stack.append(content)
    raise AssertionError(
        f"no RSA public key found in the certificate served by SigningCertURL "
        f"({len(der)} DER bytes)"
    )


def _verify_pkcs1v15(signed: bytes, signature: bytes, modulus: int, exponent: int,
                     version: str) -> bool:
    """RSASSA-PKCS1-v1_5 verify, pure Python, with the digest the SignatureVersion selects."""
    hasher, prefix = _DIGESTS[version]
    k = (modulus.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    em = pow(int.from_bytes(signature, "big"), exponent, modulus).to_bytes(k, "big")
    digest = hasher(signed).digest()
    ps_len = k - len(prefix) - len(digest) - 3
    if ps_len < 8:
        return False
    expected = b"\x00\x01" + b"\xff" * ps_len + b"\x00" + prefix + digest
    return em == expected


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real", "Value": _SCENARIO},
            {"Key": "sim2real:managed", "Value": "true"}]


def _create_topic(ctx, *, attributes: dict | None = None) -> str:
    """CreateTopic (tagged + prefix-named) and register DeleteTopic immediately."""
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-sns-t-")
    arn = sns.create_topic(
        Name=name, Attributes=dict(attributes or {}), Tags=_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda a=arn: ctx.client("sns").delete_topic(TopicArn=a))
    return arn


def _create_queue_for_topic(ctx, topic_arn: str) -> tuple[str, str]:
    """Create a real SQS queue whose policy lets exactly this topic publish to it."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-sns-q-")
    url = sqs.create_queue(
        QueueName=name,
        tags={"sim2real": _SCENARIO, "sim2real:managed": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda u=url: ctx.client("sqs").delete_queue(QueueUrl=u))
    arn = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
        }],
    }
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    return url, arn


def _subscribe_and_confirm(ctx, topic_arn: str, queue_arn: str, *,
                           attributes: dict | None = None,
                           timeout_s: float = 60.0) -> str:
    """Subscribe an SQS queue and poll GetSubscriptionAttributes until it is confirmed."""
    sns = ctx.client("sns")
    kwargs: dict = {"TopicArn": topic_arn, "Protocol": "sqs", "Endpoint": queue_arn,
                    "ReturnSubscriptionArn": True}
    if attributes:
        kwargs["Attributes"] = attributes
    sub_arn = sns.subscribe(**kwargs)["SubscriptionArn"]
    ctx.on_cleanup(lambda s=sub_arn: ctx.client("sns").unsubscribe(SubscriptionArn=s))
    _poll_until(
        lambda: sns.get_subscription_attributes(
            SubscriptionArn=sub_arn)["Attributes"].get("PendingConfirmation"),
        lambda pending: pending == "false",
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"subscription {sub_arn} leaves PendingConfirmation",
    )
    return sub_arn


def _poll_until(fn, pred, *, timeout_s: float, interval_s: float, description: str):
    """Bounded retry; raise on the deadline."""
    deadline = time.monotonic() + timeout_s
    value = fn()
    while not pred(value):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: not satisfied within {timeout_s}s, last value {value!r}"
            )
        time.sleep(interval_s)
        value = fn()
    return value


def _error(fn) -> tuple[str | None, str]:
    """(Code, Message) for a refused call; raise on unexpected success."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(
        "expected this call to be refused, but it succeeded; an over-permissive target must "
        "not be able to report a missing error code instead of an unexpected success"
    )


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    import ssl

    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
