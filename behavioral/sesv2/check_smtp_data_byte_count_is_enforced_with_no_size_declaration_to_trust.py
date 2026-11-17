"""smtp-data-byte-count-is-enforced-with-no-size-declaration-to-trust."""
# SES advertises no RFC 1870 SIZE extension on port 465, so the documented, non-adjustable 40 MB
# message ceiling (quotas.html) is pinned with a several-megabyte margin on both sides.
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import smtplib
import socket
import ssl
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "smtp-data-byte-count-is-enforced-with-no-size-declaration-to-trust"
GROUP = "rejected"
SERVICES = ["sesv2"]

# ===== helpers =====
# The EHLO reply is read off a raw TLS socket so the capability keywords are seen exactly as
# SES sends them.

_SMTP_PORT = 465  # implicit TLS ("TLS Wrapper", smtp-connect.html); the only port the runner reaches
_CONNECT_TIMEOUT_S = 30.0
#: The deadline for a full-size DATA stream.
_DATA_STREAM_TIMEOUT_S = 600.0
_AUTH_CONVERGENCE_DEADLINE_S = 150.0
_AUTH_RETRY_INTERVAL_S = 5.0

# https://docs.aws.amazon.com/ses/latest/dg/smtp-credentials.html
_DERIVE_DATE = "11111111"
_DERIVE_SERVICE = "ses"
_DERIVE_TERMINAL = "SendRawEmail"
_DERIVE_VERSION = 0x04

_RECIPIENT = "success@simulator.amazonses.com"

#: quotas.html, "Message quotas": the SMTP/v2-API message-size ceiling is 40 MB, "Adjustable: No" —
#: a fixed constant identical across every account, not a value read from the target, because the
#: target advertises no such value at all.
#: "40 MB" is read generously on both sides: _UNDER_BYTES sits below even the smaller decimal
#: reading (40,000,000) and _OVER_BYTES sits above even the larger binary reading (41,943,040), so
#: the ambiguity itself cannot flip either verdict.
_UNDER_BYTES = 38_000_000
_OVER_BYTES = 43_000_000
#: Substrings that make a refusal attributable to the message SIZE rather than anything else.
#: "too long" is what SES says ("5.3.4 Message is too long.",
#: 5.3.4 being RFC 3463's enhanced status code for "message too big for system") — kept alongside
#: the RFC 1870 s6.2 wording ("exceeds ... size") and other common phrasings in case the exact
#: text varies by frontend.
_SIZE_MARKERS = ("size", "too large", "exceed", "too big", "too long")

_DATAPLANE_SENTINEL = "DATAPLANE_UNIMPLEMENTED"


def _smtp_password(secret_access_key: str, region: str) -> str:
    """base64(0x04 || HMAC-chain) — the SES SMTP password derived from an IAM secret key."""

    def _sign(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    signature = _sign(("AWS4" + secret_access_key).encode("utf-8"), _DERIVE_DATE)
    for element in (region, _DERIVE_SERVICE, "aws4_request", _DERIVE_TERMINAL):
        signature = _sign(signature, element)
    return base64.b64encode(bytes([_DERIVE_VERSION]) + signature).decode("ascii")


def _tls_socket(host: str, port: int) -> ssl.SSLSocket:
    """A hand-rolled TLS socket. A connect or handshake failure carries the data-plane sentinel:
    nothing listening is a fidelity finding about the target, not an environment error."""
    try:
        raw = socket.create_connection((host, port), timeout=_CONNECT_TIMEOUT_S)
    except OSError as exc:
        raise AssertionError(
            f"{_DATAPLANE_SENTINEL}: nothing accepted a TCP connection on {host}:{port}; the SES "
            f"SMTP submission data plane is a separate listener from the signed API ({exc!r})"
        ) from exc
    try:
        sock = ssl._create_unverified_context().wrap_socket(raw, server_hostname=host)
    except (ssl.SSLError, OSError) as exc:
        raw.close()
        raise AssertionError(
            f"{_DATAPLANE_SENTINEL}: {host}:{port} accepted TCP but completed no TLS handshake; "
            f"smtp-connect.html requires every SES SMTP connection to be encrypted ({exc!r})"
        ) from exc
    sock.settimeout(_CONNECT_TIMEOUT_S)
    return sock


def _read_reply(sock: ssl.SSLSocket) -> list[str]:
    """One complete SMTP reply, continuation lines included, as sent."""
    buf = b""
    deadline = time.monotonic() + _CONNECT_TIMEOUT_S
    while time.monotonic() < deadline:
        chunk = sock.recv(4096)
        if not chunk:
            raise AssertionError(f"the SMTP listener closed the connection mid-reply after {buf!r}")
        buf += chunk
        lines = buf.split(b"\r\n")
        if len(lines) >= 2 and lines[-1] == b"" and len(lines[-2]) >= 4 and lines[-2][3:4] == b" ":
            return [line.decode("ascii", "replace") for line in lines[:-1]]
    raise AssertionError(
        f"the SMTP listener sent no complete reply within {_CONNECT_TIMEOUT_S}s; buffer was {buf!r}"
    )


def _ehlo_capabilities(host: str, port: int) -> dict[str, str]:
    """{KEYWORD: parameter-text} from the EHLO response, plus the greeting checks that prove the
    listener is SES rather than something else answering on 465."""
    sock = _tls_socket(host, port)
    try:
        greeting = _read_reply(sock)
        assert greeting and "ESMTP SimpleEmailService" in greeting[0], (
            f"the SMTP greeting on {host}:{port} was {greeting!r} and does not name the SES "
            f"SMTP server"
        )
        sock.sendall(b"EHLO sim2real.behavioral.probe\r\n")
        reply = _read_reply(sock)
    finally:
        sock.close()
    caps: dict[str, str] = {}
    for line in reply[1:]:
        token = line[4:].strip()
        if token:
            keyword, _, params = token.partition(" ")
            caps[keyword.upper()] = params.strip()
    return caps


def _delete_user_verified(iam, user: str, policy: str) -> None:
    """A long-lived IAM access key is a real credential: teardown is verified, not best-effort.
    ctx.on_cleanup swallows exceptions, so print the leak before raising."""
    try:
        for meta in iam.list_access_keys(UserName=user)["AccessKeyMetadata"]:
            iam.delete_access_key(UserName=user, AccessKeyId=meta["AccessKeyId"])
        iam.delete_user_policy(UserName=user, PolicyName=policy)
        iam.delete_user(UserName=user)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code == "NoSuchEntity":
            return
        print(f"LEAK: could not tear down IAM user {user}: {code!r}")
        raise AssertionError(f"could not tear down IAM user {user}: {code!r}") from exc
    try:
        iam.get_user(UserName=user)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
            return
        raise
    print(f"LEAK: IAM user {user} still present after delete_user")
    raise AssertionError(f"IAM user {user} still present after delete_user")


def _authed(host: str, port: int, access_key_id: str, password: str) -> smtplib.SMTP_SSL:
    """An authenticated session with a socket timeout wide enough for a full-size DATA stream, and a
    bounded AUTH convergence retry that RAISES on its deadline."""
    deadline = time.monotonic() + _AUTH_CONVERGENCE_DEADLINE_S
    last: object = None
    attempts = 0
    while time.monotonic() < deadline:
        attempts += 1
        smtp = smtplib.SMTP_SSL(
            host,
            port,
            timeout=_DATA_STREAM_TIMEOUT_S,
            context=ssl._create_unverified_context(),
        )
        smtp.ehlo()
        try:
            code, message = smtp.login(access_key_id, password)
        except smtplib.SMTPAuthenticationError as exc:
            last = (exc.smtp_code, exc.smtp_error)
            smtp.close()
            time.sleep(_AUTH_RETRY_INTERVAL_S)
            continue
        assert (code, message) == (235, b"Authentication successful."), (
            f"AUTH with the correctly derived password answered {(code, message)!r}, expected "
            f"(235, b'Authentication successful.')"
        )
        return smtp
    raise AssertionError(
        f"the correctly derived SMTP password never authenticated on {host}:{port} within "
        f"{_AUTH_CONVERGENCE_DEADLINE_S}s ({attempts} attempts); last refusal {last!r}"
    )


@tags(
    "axis:rejection",
    "cap:c1",
    "cap:c6",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:native",
    "plane:data",
)
def run(ctx) -> None:
    """With no SIZE declaration, SES counts the DATA bytes it receives: a message safely under 40 MB
    streams to end-of-DATA and meets the identity gate, one safely over is refused with
    a size-attributable reply and counts no delivery, and the under-limit twin is accepted again."""
    iam = ctx.client("iam")
    ses = ctx.client("ses")
    sesv2 = ctx.client("sesv2")
    host, port = ctx.service_host(f"email-smtp.{ctx.region}.amazonaws.com", _SMTP_PORT)

    assert sesv2.get_account()["SendingEnabled"] is True, (
        "setup precondition: account-level sending must be ENABLED, or a refusal at the SMTP front "
        "door cannot be attributed to the message size; GetAccount reported SendingEnabled false"
    )

    # --- what the listener CLAIMS, read before anything is asked of it. SES's EHLO on this front
    #     door advertises no SIZE extension at all — asserted here so a
    #     future SES revision that starts advertising SIZE is caught rather than silently ignored.
    caps = _ehlo_capabilities(host, port)
    assert "SIZE" not in caps, (
        f"EHLO now advertises a SIZE extension ({caps.get('SIZE')!r}); this check pinned the "
        f"documented, non-adjustable 40 MB ceiling because SES advertised none "
        f"(the expected set is {{'8BITMIME', 'AUTH', 'OK'}})"
    )

    # AWS documents that SMTP credentials cannot be derived from temporary credentials, so the check
    # mints a long-lived key of its own rather than reusing the harness session.
    user = ctx.unique_name("sim2real-behav-smtp-bytes-")
    policy = "sim2real-ses-send-raw-email"
    iam.create_user(UserName=user, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_user_verified(iam, user, policy))
    iam.put_user_policy(
        UserName=user,
        PolicyName=policy,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": ["ses:SendRawEmail"], "Resource": "*"}],
            }
        ),
    )
    key = iam.create_access_key(UserName=user)["AccessKey"]
    access_key_id, secret = key["AccessKeyId"], key["SecretAccessKey"]
    password = _smtp_password(secret, ctx.region)

    sender_domain = ctx.unique_name("sim2real-behav-bytes-") + ".example.com"
    sender = f"noreply@{sender_domain}"
    stats_before = ses.get_send_statistics()["SendDataPoints"]

    def _payload(total_bytes: int) -> bytes:
        """A well-formed RFC 5322 message whose WIRE length is exactly *total_bytes*, excluding the
        terminating `.` line. Filler is 'x' in 76-column lines, so nothing needs dot-stuffing and no
        line exceeds the 998-octet limit of RFC 5322 s2.1.1."""
        headers = (
            f"From: {sender}\r\nTo: {_RECIPIENT}\r\n"
            f"Subject: sim2real smtp byte-count probe\r\n"
            f"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=US-ASCII\r\n\r\n"
        ).encode()
        remaining = total_bytes - len(headers)
        assert remaining > 0, (
            f"the requested payload of {total_bytes} bytes is smaller than the {len(headers)}-byte "
            f"header block; the margin is too small to build a well-formed message"
        )
        line = b"x" * 76 + b"\r\n"
        body = (line * (remaining // len(line)))[:remaining]
        # Pad the last partial line back up to exactly `remaining` bytes with filler, never a bare CR.
        if len(body) < remaining:
            body += b"x" * (remaining - len(body))
        payload = headers + body
        assert len(payload) == total_bytes, (
            f"payload construction is off: wanted {total_bytes} bytes, built {len(payload)}"
        )
        return payload

    def _stream(total_bytes: int, note: str) -> tuple[str, int, str]:
        """Authenticate, open a transaction, stream *total_bytes* with NO SIZE declaration anywhere,
        and return (phase, code, text). A dropped connection is reported as its own outcome and
        RAISES — 'the server refused' and 'the connection died' are different contracts."""
        smtp = _authed(host, port, access_key_id, password)
        try:
            code, message = smtp.docmd("MAIL", f"FROM:<{sender}>")
            if code != 250:
                return ("mail-from", code, message.decode("ascii", "replace"))
            code, message = smtp.docmd("RCPT", f"TO:<{_RECIPIENT}>")
            if code != 250:
                return ("rcpt-to", code, message.decode("ascii", "replace"))
            code, message = smtp.docmd("DATA")
            if code != 354:
                return ("data", code, message.decode("ascii", "replace"))
            try:
                smtp.send(_payload(total_bytes) + b"\r\n.\r\n")
                code, message = smtp.getreply()
            except (smtplib.SMTPServerDisconnected, OSError) as exc:
                raise AssertionError(
                    f"SES dropped the connection while receiving the {total_bytes}-byte message "
                    f"({note}) instead of answering it: {exc!r}. RFC 1870 permits either, so this is "
                    f"a contract to RECORD and assert explicitly — not to swallow"
                ) from exc
            return ("data-end", code, message.decode("ascii", "replace"))
        finally:
            try:
                smtp.quit()
            except (smtplib.SMTPException, OSError):
                smtp.close()

    under = _UNDER_BYTES
    over = _OVER_BYTES

    # --- Beat 1, positive control: comfortably UNDER the documented 40 MB ceiling, no declaration
    #     (none is possible — SES advertises no SIZE extension), real bytes. This is what makes the
    #     over-limit arm meaningful — without it, "refuses a large message" is indistinguishable
    #     from "refuses every message" or from a truncated stream.
    baseline = _stream(under, f"{under} bytes, under the documented 40 MB ceiling")
    assert baseline[0] == "data-end", (
        f"a {under}-byte message, under the documented 40 MB SMTP ceiling, must reach end-of-DATA; "
        f"it was refused at phase {baseline[0]!r}: {baseline[1]} {baseline[2]!r}"
    )
    assert baseline[1] == 554, (
        f"the under-limit message must be refused 554 by the IDENTITY gate — the one fault this check "
        f"never repairs — not by anything about its size; got {baseline[1]} {baseline[2]!r}"
    )
    assert baseline[2].startswith("Message rejected: Email address is not verified."), (
        f"the under-limit message must terminate on the identity gate; got {baseline[2]!r}"
    )

    # --- Beat 2, break exactly one thing: comfortably OVER the documented ceiling. Same sender, same
    #     recipient, same headers, still no `SIZE=` parameter for SES to consult (none is possible).
    oversize = _stream(over, f"{over} bytes, over the documented 40 MB ceiling")
    assert oversize[1] >= 500, (
        f"a {over}-byte message, above the documented, non-adjustable 40 MB SMTP ceiling "
        f"(quotas.html), must be refused with a permanent reply even though the client declared no "
        f"SIZE; got {oversize!r} against the under-limit baseline {baseline!r}"
    )
    assert oversize != baseline, (
        f"the over-limit message drew the identical verdict to the under-limit one ({baseline!r}); "
        f"SES is not counting the bytes it received"
    )
    oversize_text = oversize[2].lower()
    assert any(marker in oversize_text for marker in _SIZE_MARKERS), (
        f"the over-limit refusal must be attributable to the message size rather than read as a "
        f"generic permanent failure (RFC 1870 s6.2 gives 552); expected one of {_SIZE_MARKERS!r} in "
        f"{oversize[2]!r}"
    )

    # --- Beat 3, effect absent, on two independent reads: no delivery was counted and no identity was
    #     created by either refused submission.
    stats_mid = ses.get_send_statistics()["SendDataPoints"]
    assert stats_mid == stats_before, (
        f"GetSendStatistics moved from {stats_before!r} to {stats_mid!r}; neither a 554 nor a size "
        f"refusal is a delivery attempt"
    )
    try:
        identity = sesv2.get_email_identity(EmailIdentity=sender_domain)
    except ClientError as exc:
        code = (exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message"))
        assert code == ("NotFoundException", f"Email identity <{sender_domain}> does not exist."), (
            f"GetEmailIdentity for the refused sender domain raised {code!r}, expected "
            f"'NotFoundException'"
        )
    else:
        raise AssertionError(
            f"GetEmailIdentity returned {identity.get('IdentityType')!r} for {sender_domain!r} — a "
            f"refused submission must not create an identity"
        )

    # --- Beat 4, restore: the identical under-limit message is accepted to end-of-DATA again and
    #     draws the identical verdict. The size was the only thing that had changed.
    restored = _stream(under, f"restore: {under} bytes again")
    assert restored == baseline, (
        f"the identical under-limit message must draw the identical verdict after the size refusal; "
        f"expected {baseline!r}, got {restored!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
