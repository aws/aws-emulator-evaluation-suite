"""notification-signature-verifies-against-the-signing-certificate."""
from __future__ import annotations

import base64
import hashlib
import json
import time
import urllib.request

from behavioral_harness import tags

CHECK = "notification-signature-verifies-against-the-signing-certificate"
GROUP = 'server-side'
SERVICES = ['sns']

_SCENARIO = "sns-signature"

# DigestInfo DER prefixes for RSASSA-PKCS1-v1_5, keyed by the SNS SignatureVersion that selects
# the digest: version 1 signs with SHA-1, version 2 with SHA-256.
_DIGESTS = {
    "1": (hashlib.sha1, bytes.fromhex("3021300906052b0e03021a05000414")),
    "2": (hashlib.sha256, bytes.fromhex("3031300d060960864801650304020105000420")),
}


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A delivered notification's Signature verifies with the SigningCertURL certificate's public
    key over SNS's canonical string, and one flipped character of Message makes it fail, so the
    verifier is shown to check something.
    """
    sns = ctx.client("sns")
    topic_arn = _create_topic(ctx)
    queue_url, queue_arn = _create_queue_for_topic(ctx, topic_arn)
    _subscribe_and_confirm(ctx, topic_arn, queue_arn)

    declared = sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"].get(
        "SignatureVersion", "1")
    payload = ctx.unique_name("sim2real-behav-sns-signed-")
    subject = "sim2real-signed-subject"
    sns.publish(TopicArn=topic_arn, Subject=subject, Message=payload)

    envelope = json.loads(_await_body(ctx, queue_url, payload))
    assert envelope["SignatureVersion"] == declared, (
        f"the delivered SignatureVersion {envelope['SignatureVersion']!r} does not match the "
        f"topic's declared SignatureVersion {declared!r}"
    )
    version = envelope["SignatureVersion"]
    assert version in _DIGESTS, f"unexpected SignatureVersion: {version!r}"

    cert_url = envelope["SigningCertURL"]
    assert not (p := ctx.published_url_mismatch(cert_url)), p

    target_url, route_headers = ctx.endpoint_route(cert_url)
    with urllib.request.urlopen(urllib.request.Request(target_url, headers=route_headers), timeout=30) as resp:  # noqa: S310 — asserted http(s) URL
        pem = resp.read().decode("ascii")
    assert "BEGIN CERTIFICATE" in pem, f"SigningCertURL did not serve a PEM certificate: {pem[:120]!r}"
    modulus, exponent = _rsa_public_key_from_certificate(pem)

    signature = base64.b64decode(envelope["Signature"])
    canonical = _canonical_string(envelope)
    verified = _verify_pkcs1v15(canonical.encode("utf-8"), signature, modulus, exponent, version)
    assert verified is True, (
        f"the notification signature does not verify against the certificate at {cert_url!r}; "
        f"canonical string was {canonical!r}"
    )

    tampered = dict(envelope)
    tampered["Message"] = envelope["Message"][:-1] + ("X" if envelope["Message"][-1] != "X" else "Y")
    tampered_canonical = _canonical_string(tampered)
    assert tampered_canonical != canonical, (
        f"the tamper did not change the canonical string, so the negative half proves nothing: "
        f"{tampered_canonical!r}"
    )
    tampered_verified = _verify_pkcs1v15(
        tampered_canonical.encode("utf-8"), signature, modulus, exponent, version)
    assert tampered_verified is False, (
        "a tampered canonical string still verified, so the verification is not actually "
        f"checking anything (modulus bits {modulus.bit_length()}, exponent {exponent})"
    )
    assert envelope["Subject"] == subject, (
        f"the Subject that the canonical string signs was not delivered: {envelope.get('Subject')!r}"
    )


def _canonical_string(envelope: dict) -> str:
    """The string SNS signs for a Notification: field\\nvalue\\n for each signed key, in the order
    SNS documents (Message, MessageId, Subject when present, Timestamp, TopicArn, Type)."""
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
    """Extract (modulus, exponent) from an X.509 PEM certificate with no external crypto library.

    Walks the DER for the SubjectPublicKeyInfo BIT STRING whose contents parse as
    RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }. The size and exponent
    constraints reject a BIT STRING that merely happens to look like one; a wrong key would in any
    case make the signature verification below fail loudly rather than pass.
    """
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
        f"no RSA public key found in the certificate served by SigningCertURL ({len(der)} DER bytes)"
    )


def _verify_pkcs1v15(signed: bytes, signature: bytes, modulus: int, exponent: int,
                     version: str) -> bool:
    """RSASSA-PKCS1-v1_5 verify, pure Python, with the digest SNS's SignatureVersion selects."""
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
    return [{"Key": "sim2real", "Value": _SCENARIO}, {"Key": "sim2real:managed", "Value": "true"}]


def _create_topic(ctx, *, fifo: bool = False, attributes: dict | None = None) -> str:
    """CreateTopic (tagged + prefix-named) and register DeleteTopic immediately; returns the ARN."""
    sns = ctx.client("sns")
    name = ctx.unique_name("sim2real-behav-sns-t-")
    attrs = dict(attributes or {})
    if fifo:
        name = name + ".fifo"
        attrs["FifoTopic"] = "true"
    arn = sns.create_topic(Name=name, Attributes=attrs, Tags=_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda a=arn: ctx.client("sns").delete_topic(TopicArn=a))
    return arn


def _create_queue_for_topic(ctx, topic_arn: str, *, fifo: bool = False) -> tuple[str, str]:
    """Create a real SQS queue whose policy lets exactly this topic publish to it."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-sns-q-")
    attrs: dict[str, str] = {}
    if fifo:
        name = name + ".fifo"
        attrs["FifoQueue"] = "true"
    url = sqs.create_queue(
        QueueName=name, Attributes=attrs,
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
                           attributes: dict | None = None, timeout_s: float = 60.0) -> str:
    """Subscribe an SQS queue and poll GetSubscriptionAttributes until it is confirmed."""
    sns = ctx.client("sns")
    kwargs: dict = {"TopicArn": topic_arn, "Protocol": "sqs", "Endpoint": queue_arn,
                    "ReturnSubscriptionArn": True}
    if attributes:
        kwargs["Attributes"] = attributes
    sub_arn = sns.subscribe(**kwargs)["SubscriptionArn"]
    ctx.on_cleanup(lambda s=sub_arn: ctx.client("sns").unsubscribe(SubscriptionArn=s))
    deadline = time.monotonic() + timeout_s
    pending = None
    while time.monotonic() < deadline:
        pending = sns.get_subscription_attributes(
            SubscriptionArn=sub_arn)["Attributes"].get("PendingConfirmation")
        if pending == "false":
            return sub_arn
        time.sleep(1.0)
    raise AssertionError(
        f"subscription {sub_arn!r} was still PendingConfirmation={pending!r} after {timeout_s}s"
    )


def _await_body(ctx, queue_url: str, needle: str, *, timeout_s: float = 90.0) -> str:
    """Long-poll the queue until a body containing needle arrives; returns that body."""
    sqs = ctx.client("sqs")
    seen: list[str] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            body = msg.get("Body", "")
            seen.append(body)
            if needle in body:
                return body
    raise AssertionError(
        f"no message containing {needle!r} was delivered within {timeout_s}s; "
        f"bodies seen: {[b[:120] for b in seen]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
