"""smtp-session-is-a-transaction-state-machine-not-a-stateless-verb-bag."""
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

CHECK = "smtp-session-is-a-transaction-state-machine-not-a-stateless-verb-bag"
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

_RECIPIENT = "success@simulator.amazonses.com"
#: How many identical NOOPs the freeze leg issues (N consecutive identical
#: reads must return the same value and must not advance state).
_NOOP_REPEATS = 3

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
    "cap:c6",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:native",
    "plane:data",
)
def run(ctx) -> None:
    """An SES SMTP session is a transaction state machine: four out-of-sequence verbs draw the same
    permanent code, a syntax fault draws a different one, NOOP leaves an open transaction intact,
    every refusal leaves the session usable, and the ordered transaction reaches the identity gate."""
    iam = ctx.client("iam")
    ses = ctx.client("ses")
    sesv2 = ctx.client("sesv2")
    host, port = ctx.service_host(f"email-smtp.{ctx.region}.amazonaws.com", _SMTP_PORT)

    assert sesv2.get_account()["SendingEnabled"] is True, (
        "setup precondition: account-level sending must be ENABLED, or these replies cannot be "
        "attributed to command sequencing; GetAccount reported SendingEnabled false"
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
    user = ctx.unique_name("sim2real-behav-smtp-seq-")
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

    sender = f"noreply@{ctx.unique_name('sim2real-behav-seq-')}.example.com"
    stats_before = ses.get_send_statistics()["SendDataPoints"]

    smtp = _authed(host, port, access_key_id, password)
    try:

        def _cmd(verb: str, args: str = "") -> tuple[int, str]:
            code, message = smtp.docmd(verb, args) if args else smtp.docmd(verb)
            return code, message.decode("ascii", "replace")

        def _reset() -> None:
            code, text = _cmd("RSET")
            assert code == 250, (
                f"RSET must be accepted and must close any open transaction; got {code} {text!r}"
            )

        def _mail_from() -> tuple[int, str]:
            return _cmd("MAIL", f"FROM:<{sender}>")

        def _run_ordered(note: str) -> tuple[int, str]:
            """One correctly ordered transaction, all the way to end-of-DATA."""
            code, text = _mail_from()
            assert (code, text) == (250, "Ok"), (
                f"MAIL FROM must be accepted ({note}); got {code} {text!r}"
            )
            code, text = _cmd("RCPT", f"TO:<{_RECIPIENT}>")
            assert (code, text) == (250, "Ok"), (
                f"RCPT TO {_RECIPIENT!r} must be accepted ({note}); got {code} {text!r}"
            )
            code, text = _cmd("DATA")
            assert code == 354, f"DATA answered {code} {text!r}, expected 354 ({note})"
            smtp.send(
                f"From: {sender}\r\nTo: {_RECIPIENT}\r\n"
                f"Subject: sim2real smtp sequencing probe\r\n\r\n{note}\r\n.\r\n".encode()
            )
            end_code, end_message = smtp.getreply()
            return end_code, end_message.decode("ascii", "replace")

        # --- Beat 1, positive control: the ordered transaction works. Without it, "refuses RCPT
        #     before MAIL" is indistinguishable from "refuses every RCPT".
        _reset()
        baseline = _run_ordered("baseline: correctly ordered")
        assert baseline[0] == 554, (
            f"the ordered transaction must reach end-of-DATA and be refused 554 by the identity "
            f"gate; got {baseline[0]} {baseline[1]!r}"
        )
        assert baseline[1].startswith("Message rejected: Email address is not verified."), (
            f"the baseline must terminate on the IDENTITY gate, so the sequencing arms are compared "
            f"against the right thing; got {baseline[1]!r}"
        )

        # --- Beat 2, break exactly one thing, four ways. Each row is ONE verb issued in the wrong
        #     state, and each is followed immediately by the correct next verb — so a refusal can
        #     never be a poisoned session standing in for a sequencing decision.
        sequencing: dict[str, tuple[int, str]] = {}

        _reset()
        sequencing["RCPT before MAIL"] = _cmd("RCPT", f"TO:<{_RECIPIENT}>")
        code, text = _mail_from()
        assert (code, text) == (250, "Ok"), (
            f"after the refused RCPT-before-MAIL, MAIL FROM must still be accepted on the same "
            f"connection; got {code} {text!r}"
        )

        _reset()
        sequencing["DATA before MAIL"] = _cmd("DATA")
        code, text = _mail_from()
        assert (code, text) == (250, "Ok"), (
            f"after the refused DATA-before-MAIL, MAIL FROM must still be accepted; got {code} "
            f"{text!r}"
        )

        # The transaction from the previous row is open with no recipient — exactly the state this
        # row needs, so nothing is reset in between.
        sequencing["DATA before RCPT"] = _cmd("DATA")
        code, text = _cmd("RCPT", f"TO:<{_RECIPIENT}>")
        assert (code, text) == (250, "Ok"), (
            f"after the refused DATA-before-RCPT, RCPT TO must still be accepted on the same open "
            f"transaction; got {code} {text!r}"
        )

        # Still inside that transaction, which now has a recipient: a nested MAIL FROM.
        sequencing["nested MAIL"] = _mail_from()

        for label, (code, text) in sequencing.items():
            assert code >= 500, (
                f"{label} is a sequencing fault and must be refused with a permanent reply (RFC 5321 "
                f"s4.3.2 gives 503); got {code} {text!r}"
            )
        codes = {label: code for label, (code, _) in sequencing.items()}
        assert len(set(codes.values())) == 1, (
            f"all four sequencing faults are ONE fault class and must draw ONE code; got {codes!r}"
        )
        sequencing_code = next(iter(set(codes.values())))

        # --- Beat 3, the code means something: a SYNTAX fault must not draw the sequencing code. A
        #     target that answers a single generic 5xx to everything passes every row above and fails
        #     here. The probe must run on a CLOSED transaction — issuing it right after "nested MAIL"
        #     (still open) would confound a syntax fault with yet another nested-MAIL sequencing fault,
        #     which is exactly the ambiguity this beat exists to rule out.
        _reset()
        syntax_code, syntax_text = _cmd("MAIL")
        assert syntax_code >= 500, (
            f"a bare MAIL with no FROM: argument must be refused with a permanent reply (RFC 5321 "
            f"s4.2.2 gives 501); got {syntax_code} {syntax_text!r}"
        )
        assert syntax_code != sequencing_code, (
            f"a syntax fault and a sequencing fault are different faults and must draw different "
            f"codes; both answered {syntax_code} — the target is not distinguishing them"
        )

        # --- Beat 4, state must not advance on a read. Three identical NOOPs
        #     inside an open transaction: each must answer identically, and the transaction must
        #     survive all of them.
        _reset()
        code, text = _mail_from()
        assert (code, text) == (250, "Ok"), f"MAIL FROM must be accepted; got {code} {text!r}"
        code, text = _cmd("RCPT", f"TO:<{_RECIPIENT}>")
        assert (code, text) == (250, "Ok"), f"RCPT TO must be accepted; got {code} {text!r}"
        noops = [_cmd("NOOP") for _ in range(_NOOP_REPEATS)]
        assert all(code == 250 for code, _ in noops), (
            f"every NOOP must be accepted 250 (RFC 5321 s4.1.1.9); got {noops!r}"
        )
        assert len(set(noops)) == 1, (
            f"{_NOOP_REPEATS} identical NOOPs must draw {_NOOP_REPEATS} identical replies; got "
            f"{noops!r}"
        )
        code, text = _cmd("DATA")
        assert code == 354, (
            f"after {_NOOP_REPEATS} NOOPs the open transaction must still be intact, so DATA must be "
            f"accepted 354; got {code} {text!r} — a NOOP must not discard the transaction"
        )
        smtp.send(
            f"From: {sender}\r\nTo: {_RECIPIENT}\r\n"
            f"Subject: sim2real smtp noop-transparency probe\r\n\r\nnoop probe\r\n.\r\n".encode()
        )
        end_code, end_message = smtp.getreply()
        noop_verdict = (end_code, end_message.decode("ascii", "replace"))
        assert noop_verdict == baseline, (
            f"a transaction interrupted only by NOOPs must draw the identical baseline verdict "
            f"{baseline!r}; got {noop_verdict!r}"
        )

        # --- Beat 5, restore, and the terminal read at the destination: after the whole gauntlet the
        #     ordered transaction still runs to the identity gate, through the same verbs and with the
        #     same reply as before any of it.
        _reset()
        restored = _run_ordered("restore: correctly ordered after the gauntlet")
        assert restored == baseline, (
            f"after four sequencing refusals and one syntax refusal the session must still carry a "
            f"correct transaction to the "
            f"identical verdict; expected {baseline!r}, got {restored!r}"
        )
    finally:
        try:
            smtp.quit()
        except smtplib.SMTPException:
            smtp.close()

    # --- An independent side-channel: three refused messages, no delivery attempts.
    stats_after = ses.get_send_statistics()["SendDataPoints"]
    assert stats_after == stats_before, (
        f"GetSendStatistics moved from {stats_before!r} to {stats_after!r}; every message in this "
        f"check was refused and none may count as a delivery attempt"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
