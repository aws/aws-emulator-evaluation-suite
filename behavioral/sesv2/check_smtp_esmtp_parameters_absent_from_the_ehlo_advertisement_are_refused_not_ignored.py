"""smtp-esmtp-parameters-absent-from-the-ehlo-advertisement-are-refused-not-ignored."""
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

CHECK = "smtp-esmtp-parameters-absent-from-the-ehlo-advertisement-are-refused-not-ignored"
GROUP = "rejected"
SERVICES = ["sesv2"]

# ===== helpers =====
# The EHLO reply is read off a raw TLS socket rather than smtplib.esmtp_features because the
# capability keywords are the subject here and esmtp_features lower-cases them.

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

#: (verb, parameter text, the EHLO keyword that governs it). MEASURED real SES accepts every row
#: with 250 regardless of whether its keyword is in the EHLO reply — this table exists to PROVE that
#: uniformity across a deliberate mix of an advertised keyword (8BITMIME) and unadvertised ones
#: (SMTPUTF8, DSN, SIZE).
#:   SMTPUTF8   RFC 6531   internationalised addresses
#:   8BITMIME   RFC 6152   BODY=8BITMIME
#:   DSN        RFC 3461   RET= / NOTIFY= / ORCPT=
#:   SIZE       RFC 1870   SIZE=
_GOVERNED_BY: tuple[tuple[str, str, str], ...] = (
    ("MAIL", "SMTPUTF8", "SMTPUTF8"),
    ("MAIL", "BODY=8BITMIME", "8BITMIME"),
    ("MAIL", "RET=FULL", "DSN"),
    ("MAIL", "SIZE=1000", "SIZE"),
    ("RCPT", "NOTIFY=SUCCESS", "DSN"),
    ("RCPT", "ORCPT=rfc822;sim2real@example.com", "DSN"),
)
#: Two differently spelled parameters that no registry contains and no server can implement. MEASURED
#: real SES accepts both with the SAME code (250) — used for the "one acceptance class, one code"
#: stability leg, the mirror of what this table was written to detect as a refusal.
_UNKNOWN_PARAMETERS = ("XSIM2REALNOTANEXTENSION=1", "XSIM2REALALSOUNKNOWN=yes")
#: A verb no registry contains. RFC 5321 s4.2.4 gives 500 for an unrecognised command; MEASURED real
#: SES replies exactly (500, b"Error: command not implemented").
_UNKNOWN_VERB = "XSIM2REALVERB"

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
    """A hand-rolled TLS socket, so the EHLO reply is readable as sent. A connect or handshake
    failure carries the data-plane sentinel: a missing listener is a finding about the target."""
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
        # Complete when the last full line uses a SPACE at index 3 (RFC 5321 s4.2.1).
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
        assert greeting and greeting[0].startswith("220 "), (
            f"the SMTP greeting on {host}:{port} was {greeting!r}, expected a 220 line"
        )
        assert "ESMTP SimpleEmailService" in greeting[0], (
            f"the SMTP greeting {greeting[0]!r} does not name the SES SMTP server"
        )
        sock.sendall(b"EHLO sim2real.behavioral.probe\r\n")
        reply = _read_reply(sock)
    finally:
        sock.close()
    assert reply and reply[0][:3] == "250", (
        f"EHLO answered {reply!r}, expected a 250 multiline response"
    )
    caps: dict[str, str] = {}
    for line in reply[1:]:  # line 0 carries the greeting domain, never a capability
        token = line[4:].strip()
        if not token:
            continue
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
    """An authenticated session, bounded by a deadline that RAISES. A freshly minted IAM access key
    is not immediately usable on every SES SMTP frontend and no API reports when it becomes usable —
    successive connections land on different frontends."""
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
    """SES enforces its EHLO advertisement at the verb layer, not on MAIL FROM / RCPT TO parameters:
    an unrecognised verb is refused with 500 and the session survives, while advertised, unadvertised
    and unregistered parameters all draw 250, and a clean transaction still meets the identity gate."""
    iam = ctx.client("iam")
    ses = ctx.client("ses")
    sesv2 = ctx.client("sesv2")
    host, port = ctx.service_host(f"email-smtp.{ctx.region}.amazonaws.com", _SMTP_PORT)

    # Rule out an account-level pause, which would change every reply below for reasons that have
    # nothing to do with parameter handling.
    assert sesv2.get_account()["SendingEnabled"] is True, (
        "setup precondition: account-level sending must be ENABLED, or a refusal at the SMTP front "
        "door cannot be attributed to the parameter under test; GetAccount said otherwise"
    )

    caps = _ehlo_capabilities(host, port)
    assert "AUTH" in caps, (
        f"EHLO advertised {sorted(caps)!r} with no AUTH keyword; SES must offer authentication on "
        f"the TLS listener, and the whole table below needs an authenticated session"
    )
    unadvertised_rows = [row for row in _GOVERNED_BY if row[2] not in caps]
    advertised_rows = [row for row in _GOVERNED_BY if row[2] in caps]
    assert unadvertised_rows, (
        f"the table needs at least one governed parameter SES did NOT advertise, or uniform "
        f"acceptance below would be indistinguishable from every keyword simply being advertised; "
        f"SES advertised every keyword in {sorted({r[2] for r in _GOVERNED_BY})!r} (advertised set: "
        f"{sorted(caps)!r})"
    )
    assert advertised_rows, (
        f"the table needs at least one governed parameter SES DID advertise, or uniform acceptance "
        f"below would be indistinguishable from every keyword simply being unadvertised; advertised "
        f"set was {sorted(caps)!r} against governing keywords "
        f"{sorted({r[2] for r in _GOVERNED_BY})!r}"
    )

    # AWS documents that SMTP credentials cannot be derived from temporary credentials, so the check
    # mints a long-lived key of its own rather than reusing the harness session.
    user = ctx.unique_name("sim2real-behav-smtp-esmtp-")
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

    sender = f"noreply@{ctx.unique_name('sim2real-behav-esmtp-')}.example.com"
    stats_before = ses.get_send_statistics()["SendDataPoints"]

    smtp = _authed(host, port, access_key_id, password)
    try:

        def _reset() -> None:
            code, message = smtp.docmd("RSET")
            assert code == 250, f"RSET must be accepted between probes; got {code} {message!r}"

        def _bare_mail_from() -> tuple[int, bytes]:
            return smtp.docmd("MAIL", f"FROM:<{sender}>")

        # --- Beat 1, positive control: a MAIL FROM with NO parameters at all is accepted, so every
        #     refusal below is attributable to the parameter and not to the address or the session.
        code, message = _bare_mail_from()
        assert (code, message) == (250, b"Ok"), (
            f"a parameterless MAIL FROM:<{sender}> must be accepted; got {code} {message!r}"
        )

        # --- Beat 2, break exactly one thing: append a parameter no registry contains. Twice, with
        #     two different spellings, so the code asserted is an ACCEPTANCE CLASS rather than a
        #     coincidence: SES answers 250 to both.
        unknown_codes = {}
        for parameter in _UNKNOWN_PARAMETERS:
            _reset()
            code, message = smtp.docmd("MAIL", f"FROM:<{sender}> {parameter}")
            assert (code, message) == (250, b"Ok"), (
                f"MAIL FROM carrying the unregistered parameter {parameter!r} was measured accepted "
                f"(250 Ok) on real SES — it does not gate MAIL FROM/RCPT TO parameters on extension "
                f"registration; got {code} {message!r}"
            )
            unknown_codes[parameter] = code

            # --- Beat 3, effect PRESENT, not absent: the accepted parameter really opened a live
            #     transaction — RCPT TO after it succeeds too, proving this is a genuine accept and
            #     not a fluke double-answer.
            live_code, live_message = smtp.docmd("RCPT", f"TO:<{_RECIPIENT}>")
            assert (live_code, live_message) == (250, b"Ok"), (
                f"after MAIL FROM carrying {parameter!r} was accepted, RCPT TO must also be accepted "
                f"— a genuinely open transaction, not a parameter that was accepted and then "
                f"silently voided; got {live_code} {live_message!r}"
            )
        assert len(set(unknown_codes.values())) == 1, (
            f"two unregistered parameters are one acceptance class and must draw one code; got "
            f"{unknown_codes!r}"
        )

        # --- Beat 4, the one thing that IS closed: an unrecognised VERB (not a parameter — an entire
        #     unknown command) is refused with the measured literal, and does not tear the session
        #     down (the following bare MAIL FROM still succeeds).
        _reset()
        verb_code, verb_message = smtp.docmd(_UNKNOWN_VERB)
        assert (verb_code, verb_message) == (500, b"Error: command not implemented"), (
            f"the unrecognised verb {_UNKNOWN_VERB!r} must be refused with the measured reply "
            f"(RFC 5321 s4.2.4 gives 500 for this class); got {verb_code} {verb_message!r}"
        )

        _reset()
        code, message = _bare_mail_from()
        assert (code, message) == (250, b"Ok"), (
            f"a bare MAIL FROM right after the unrecognised-verb refusal must still be accepted, "
            f"proving the refusal did not tear the session down; got {code} {message!r}"
        )

        # --- Beat 5, the advertisement does NOT decide for MAIL/RCPT parameters: every row is
        #     accepted whether or not its governing keyword was advertised — the mirror of the
        #     AUTH-mechanism closure, deliberately exercised across a mix of one
        #     advertised keyword (8BITMIME) and several unadvertised ones (SMTPUTF8, DSN, SIZE).
        for verb, parameter, keyword in _GOVERNED_BY:
            _reset()
            if verb == "RCPT":
                mail_code, mail_message = _bare_mail_from()
                assert (mail_code, mail_message) == (250, b"Ok"), (
                    f"a transaction must be open before probing the RCPT parameter {parameter!r}; "
                    f"MAIL FROM answered {mail_code} {mail_message!r}"
                )
                code, message = smtp.docmd("RCPT", f"TO:<{_RECIPIENT}> {parameter}")
            else:
                code, message = smtp.docmd("MAIL", f"FROM:<{sender}> {parameter}")
            assert (code, message) == (250, b"Ok"), (
                f"{verb} carrying {parameter!r} (governed by {keyword!r}, advertised="
                f"{keyword in caps}) must be accepted 250 regardless of advertisement — real SES "
                f"does not gate MAIL/RCPT parameter acceptance on its own EHLO reply "
                f"(advertised set: {sorted(caps)!r}); got {code} {message!r}"
            )

        # --- Beat 6, terminal read at the destination, through different verbs than any above: a
        #     clean ordered transaction still runs to end-of-DATA, where the one fault this check
        #     never repaired — the unverified sender — is what answers.
        _reset()
        code, message = _bare_mail_from()
        assert (code, message) == (250, b"Ok"), (
            f"the closing transaction's MAIL FROM must be accepted; got {code} {message!r}"
        )
        code, message = smtp.docmd("RCPT", f"TO:<{_RECIPIENT}>")
        assert (code, message) == (250, b"Ok"), (
            f"RCPT TO {_RECIPIENT!r} must be accepted on the closing transaction; got {code} "
            f"{message!r}"
        )
        code, message = smtp.docmd("DATA")
        assert code == 354, f"DATA answered {code} {message!r}, expected 354"
        smtp.send(
            f"From: {sender}\r\nTo: {_RECIPIENT}\r\n"
            f"Subject: sim2real esmtp-parameter closure probe\r\n\r\n"
            f"advertised={sorted(caps)}\r\n.\r\n".encode()
        )
        end_code, end_message = smtp.getreply()
        end_text = end_message.decode("ascii", "replace")
        assert end_code == 554, (
            f"end-of-DATA for the unverified sender must be 554; got {end_code} {end_text!r}"
        )
        assert end_text.startswith("Message rejected: Email address is not verified."), (
            f"the closing transaction must reach the IDENTITY gate, proving the parameter probes "
            f"neither poisoned nor short-circuited the session; got {end_text!r}"
        )
    finally:
        try:
            smtp.quit()
        except smtplib.SMTPException:
            smtp.close()

    # --- An independent side-channel: none of this was a delivery attempt.
    stats_after = ses.get_send_statistics()["SendDataPoints"]
    assert stats_after == stats_before, (
        f"GetSendStatistics moved from {stats_before!r} to {stats_after!r}; refused parameters and a "
        f"554 refusal are all non-deliveries and must not be counted"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
