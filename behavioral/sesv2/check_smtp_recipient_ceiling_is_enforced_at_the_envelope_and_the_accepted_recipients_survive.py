"""smtp-recipient-ceiling-is-enforced-at-the-envelope-and-the-accepted-recipients-survive."""
# The 50-recipients-per-message ceiling is documented as non-adjustable (quotas.html), and the
# mailbox simulator's labelled addresses (success+label@) supply 51 distinct deliverable recipients.
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

CHECK = "smtp-recipient-ceiling-is-enforced-at-the-envelope-and-the-accepted-recipients-survive"
GROUP = "rejected"
SERVICES = ["sesv2"]

# ===== helpers =====
# The banner is read through a raw TLS socket because smtplib discards the greeting text.

_SMTP_PORT = 465  # implicit TLS ("TLS Wrapper", smtp-connect.html); the only port the runner reaches
_CONNECT_TIMEOUT_S = 30.0
_AUTH_CONVERGENCE_DEADLINE_S = 150.0
_AUTH_RETRY_INTERVAL_S = 5.0

# https://docs.aws.amazon.com/ses/latest/dg/smtp-credentials.html
_DERIVE_DATE = "11111111"
_DERIVE_SERVICE = "ses"
_DERIVE_TERMINAL = "SendRawEmail"
_DERIVE_VERSION = 0x04

#: quotas.html, "Sender and recipient quotas": 50 recipients per message, Adjustable: No. Identical on
#: every account and non-adjustable, so pinning it is the contract rather than a quota assumption.
_RECIPIENT_CEILING = 50
#: Substrings that make a refusal attributable to the RECIPIENT COUNT rather than to anything else.
_RECIPIENT_MARKERS = ("recipient", "too many")

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
    """An authenticated session, bounded by a deadline that RAISES. A freshly minted IAM access key is
    not immediately usable on every SES SMTP frontend and no API reports when it becomes usable."""
    deadline = time.monotonic() + _AUTH_CONVERGENCE_DEADLINE_S
    last: object = None
    attempts = 0
    while time.monotonic() < deadline:
        attempts += 1
        smtp = smtplib.SMTP_SSL(
            host, port, timeout=_CONNECT_TIMEOUT_S, context=ssl._create_unverified_context()
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
    "concern:data-plane",
    "concern:negative-classes",
    "dp:native",
    "plane:data",
)
def run(ctx) -> None:
    """SES enforces its 50-recipient ceiling over SMTP: 50 RCPT TO are accepted, and the 51st is either
    refused with a stable recipient-attributable reply while the 50 survive to end-of-DATA, or the
    message is refused unlike the in-limit one; a fresh 50-recipient transaction is accepted again."""
    iam = ctx.client("iam")
    ses = ctx.client("ses")
    sesv2 = ctx.client("sesv2")
    host, port = ctx.service_host(f"email-smtp.{ctx.region}.amazonaws.com", _SMTP_PORT)

    # Rule out an account-level pause, which would change every reply below for an unrelated reason.
    assert sesv2.get_account()["SendingEnabled"] is True, (
        "setup precondition: account-level sending must be ENABLED, or a refusal at the SMTP front "
        "door cannot be attributed to the recipient count; GetAccount said otherwise"
    )

    sock = _tls_socket(host, port)
    try:
        banner = sock.recv(512).decode("ascii", "replace")
    finally:
        sock.close()
    assert "ESMTP SimpleEmailService" in banner, (
        f"the SMTP greeting on {host}:{port} was {banner!r} and does not name the SES SMTP "
        f"server"
    )

    # AWS documents that SMTP credentials cannot be derived from temporary credentials, so the check
    # mints a long-lived key of its own rather than reusing the harness session.
    user = ctx.unique_name("sim2real-behav-smtp-rcpt-")
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

    sender = f"noreply@{ctx.unique_name('sim2real-behav-rcpt-')}.example.com"
    # 51 DISTINCT deliverable recipients, via the mailbox simulator's documented labelling. Distinct,
    # because a ceiling on recipients cannot be probed with one address repeated — a server that
    # deduplicates would never reach it.
    run_label = ctx.unique_name("sim2real-")
    recipients = [
        f"success+{run_label}-{index:02d}@simulator.amazonses.com"
        for index in range(_RECIPIENT_CEILING + 1)
    ]
    assert len(set(recipients)) == _RECIPIENT_CEILING + 1, (
        f"the {_RECIPIENT_CEILING + 1} probe recipients must be distinct; got "
        f"{len(set(recipients))} unique out of {len(recipients)}"
    )
    stats_before = ses.get_send_statistics()["SendDataPoints"]

    def _open_transaction(smtp: smtplib.SMTP_SSL) -> None:
        code, message = smtp.docmd("MAIL", f"FROM:<{sender}>")
        assert (code, message) == (250, b"Ok"), (
            f"MAIL FROM:<{sender}> must be accepted; got {code} {message!r}"
        )

    def _finish(smtp: smtplib.SMTP_SSL, note: str) -> tuple[int, str]:
        code, message = smtp.docmd("DATA")
        assert code == 354, f"DATA answered {code} {message!r}, expected 354 ({note})"
        smtp.send(
            f"From: {sender}\r\nTo: {recipients[0]}\r\n"
            f"Subject: sim2real smtp recipient-ceiling probe\r\n\r\n{note}\r\n.\r\n".encode()
        )
        end_code, end_message = smtp.getreply()
        return end_code, end_message.decode("ascii", "replace")

    # --- Beat 1, positive control: exactly the documented ceiling is accepted, one RCPT at a time,
    #     and the transaction runs to the identity gate. This is also what makes the 51st meaningful:
    #     without it, "refuses 51 recipients" is indistinguishable from "refuses every RCPT TO".
    smtp = _authed(host, port, access_key_id, password)
    try:
        _open_transaction(smtp)
        for index, recipient in enumerate(recipients[:_RECIPIENT_CEILING]):
            code, message = smtp.docmd("RCPT", f"TO:<{recipient}>")
            assert (code, message) == (250, b"Ok"), (
                f"recipient {index + 1} of {_RECIPIENT_CEILING} ({recipient!r}) must be accepted — "
                f"quotas.html puts the non-adjustable ceiling at {_RECIPIENT_CEILING}; got {code} "
                f"{message!r}"
            )
        baseline_code, baseline_text = _finish(smtp, "baseline: exactly the ceiling")
        assert baseline_code == 554, (
            f"the {_RECIPIENT_CEILING}-recipient baseline must reach end-of-DATA and be refused 554 "
            f"by the identity gate; got {baseline_code} {baseline_text!r}"
        )
        assert baseline_text.startswith("Message rejected: Email address is not verified."), (
            f"the baseline must terminate on the IDENTITY gate, so the over-limit arm is compared "
            f"against the right thing; got {baseline_text!r}"
        )
    finally:
        try:
            smtp.quit()
        except smtplib.SMTPException:
            smtp.close()

    # --- Beat 2, break exactly one thing: the same transaction with ONE more recipient. A fresh
    #     session, because SES closes an idle authenticated connection with
    #     `451 4.4.2 Timeout waiting for data from client.` and that timeout would be graded here.
    smtp = _authed(host, port, access_key_id, password)
    try:
        _open_transaction(smtp)
        for index, recipient in enumerate(recipients[:_RECIPIENT_CEILING]):
            code, message = smtp.docmd("RCPT", f"TO:<{recipient}>")
            assert (code, message) == (250, b"Ok"), (
                f"recipient {index + 1} must still be accepted in the over-limit arm; got {code} "
                f"{message!r}"
            )
        over_code, over_message = smtp.docmd("RCPT", f"TO:<{recipients[_RECIPIENT_CEILING]}>")
        over_text = over_message.decode("ascii", "replace")

        # SES does not document the SMTP phase that enforces the ceiling, so each phase is held to
        # its own contract.
        if over_code != 250:
            # --- SES refuses the 51st recipient itself.
            assert over_code >= 400, (
                f"recipient {_RECIPIENT_CEILING + 1} must be refused, not answered {over_code} "
                f"{over_text!r}"
            )
            assert any(marker in over_text.lower() for marker in _RECIPIENT_MARKERS), (
                f"the over-limit refusal must be attributable to the recipient count rather than "
                f"read as a generic failure (RFC 5321 s4.5.3.1 pairs 452 with 'too many "
                f"recipients'); expected one of {_RECIPIENT_MARKERS!r} in {over_text!r}"
            )
            # Stability: one fault, one answer. A target that answers whichever error it noticed
            # first fails here.
            again_code, again_message = smtp.docmd("RCPT", f"TO:<{recipients[_RECIPIENT_CEILING]}>")
            assert (again_code, again_message.decode("ascii", "replace")) == (
                over_code,
                over_text,
            ), (
                f"the identical over-limit RCPT TO must draw the identical refusal; first "
                f"{(over_code, over_text)!r}, second "
                f"{(again_code, again_message.decode('ascii', 'replace'))!r}"
            )
            # --- Beat 3, the survival leg and the whole point of testing this at SMTP: the
            #     recipients already accepted are still accepted, so DATA proceeds and the message
            #     terminates on the identity gate exactly as the baseline did.
            survived_code, survived_text = _finish(smtp, "over-limit: the accepted 50 must survive")
            assert (survived_code, survived_text) == (baseline_code, baseline_text), (
                f"a refused {_RECIPIENT_CEILING + 1}st recipient must not invalidate the "
                f"{_RECIPIENT_CEILING} already accepted: expected the baseline verdict "
                f"{(baseline_code, baseline_text)!r}, got {(survived_code, survived_text)!r}"
            )
        else:
            # --- SES accepted the 51st and must refuse the MESSAGE instead. Then the enforcement is
            #     deferred, and the contract is that the over-limit message is refused DIFFERENTLY
            #     from the in-limit one.
            deferred_code, deferred_text = _finish(smtp, "over-limit: deferred enforcement")
            assert (deferred_code, deferred_text) != (baseline_code, baseline_text), (
                f"SES accepted a {_RECIPIENT_CEILING + 1}st RCPT TO, so the ceiling must be enforced "
                f"at end-of-DATA instead — but the verdict was the identical baseline "
                f"{(baseline_code, baseline_text)!r}, i.e. the documented "
                f"{_RECIPIENT_CEILING}-recipient ceiling is not enforced on this front door at all"
            )
            assert any(marker in deferred_text.lower() for marker in _RECIPIENT_MARKERS), (
                f"the deferred over-limit refusal must be attributable to the recipient count; "
                f"expected one of {_RECIPIENT_MARKERS!r} in {deferred_text!r}"
            )
    finally:
        try:
            smtp.quit()
        except smtplib.SMTPException:
            smtp.close()

    # --- Beat 4, restore: a fresh transaction at exactly the ceiling is accepted again and draws the
    #     identical baseline verdict. The recipient count was the only thing that had changed.
    smtp = _authed(host, port, access_key_id, password)
    try:
        _open_transaction(smtp)
        for recipient in recipients[:_RECIPIENT_CEILING]:
            code, message = smtp.docmd("RCPT", f"TO:<{recipient}>")
            assert (code, message) == (250, b"Ok"), (
                f"after the over-limit refusal, {recipient!r} must be accepted again; got {code} "
                f"{message!r}"
            )
        restored_code, restored_text = _finish(smtp, "restore: back to exactly the ceiling")
        assert (restored_code, restored_text) == (baseline_code, baseline_text), (
            f"a fresh {_RECIPIENT_CEILING}-recipient transaction must draw the identical baseline "
            f"verdict; expected {(baseline_code, baseline_text)!r}, got "
            f"{(restored_code, restored_text)!r}"
        )
    finally:
        try:
            smtp.quit()
        except smtplib.SMTPException:
            smtp.close()

    # --- An independent side-channel: three refused messages, no delivery attempts. The mailbox
    #     simulator does not affect the daily quota, but these never reached it anyway.
    stats_after = ses.get_send_statistics()["SendDataPoints"]
    assert stats_after == stats_before, (
        f"GetSendStatistics moved from {stats_before!r} to {stats_after!r} across three refused "
        f"messages; a rejected message must not be counted as a delivery attempt"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
