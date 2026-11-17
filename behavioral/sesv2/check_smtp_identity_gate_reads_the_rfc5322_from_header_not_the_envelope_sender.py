"""smtp-identity-gate-reads-the-rfc5322-from-header-not-the-envelope-sender."""
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

CHECK = "smtp-identity-gate-reads-the-rfc5322-from-header-not-the-envelope-sender"
GROUP = "rejected"
SERVICES = ["sesv2"]

# ===== helpers =====
# The banner is read through a raw TLS socket because smtplib.SMTP_SSL consumes the 220 greeting
# into a reply tuple and discards the text.

_SMTP_PORT = 465  # implicit TLS ("TLS Wrapper", smtp-connect.html); the only port the runner reaches
_CONNECT_TIMEOUT_S = 30.0
#: How long a freshly minted IAM access key may take to become usable on the SMTP frontends. No API
#: reports when it happens and successive connections land on different frontends, so this is a
#: bounded retry with a deadline that RAISES, never a sleep.
_AUTH_CONVERGENCE_DEADLINE_S = 150.0
_AUTH_RETRY_INTERVAL_S = 5.0
#: The credential-propagation race that _AUTH_CONVERGENCE_DEADLINE_S guards at
#: the AUTH command can also surface AFTER a successful 235, as a `535 Authentication Credentials
#: Invalid` on the end-of-DATA reply of that same connection. `_submit` retries the WHOLE
#: transaction (fresh connection, fresh AUTH) on that exact signature, bounded by this deadline.
_TRANSACTION_RETRY_DEADLINE_S = 60.0
_TRANSACTION_RETRY_INTERVAL_S = 5.0

# The SigV4-shaped chain SES documents for converting an IAM secret key into an SMTP password:
# https://docs.aws.amazon.com/ses/latest/dg/smtp-credentials.html
_DERIVE_DATE = "11111111"
_DERIVE_SERVICE = "ses"
_DERIVE_TERMINAL = "SendRawEmail"
_DERIVE_VERSION = 0x04

# The mailbox simulator: a real deliverable recipient that never leaves SES. It exempts the
# RECIPIENT from the sandbox's verification requirement and says nothing about the SENDER, which is
# precisely the arm this check wants — every submission below is EXPECTED to be refused.
# `success@` rather than `bounce@`/`complaint@`: neither a bounce nor a complaint is wanted against
# this account's reputation.
_RECIPIENT = "success@simulator.amazonses.com"

#: Marks a failure as a missing SMTP listener on the target, distinct from a driver-level
#: "Connection refused".
_DATAPLANE_SENTINEL = "DATAPLANE_UNIMPLEMENTED"


def _smtp_password(secret_access_key: str, region: str) -> str:
    """base64(0x04 || HMAC-chain) — the SES SMTP password derived from an IAM secret key."""

    def _sign(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    signature = _sign(("AWS4" + secret_access_key).encode("utf-8"), _DERIVE_DATE)
    for element in (region, _DERIVE_SERVICE, "aws4_request", _DERIVE_TERMINAL):
        signature = _sign(signature, element)
    return base64.b64encode(bytes([_DERIVE_VERSION]) + signature).decode("ascii")


# tls-subject: the check asserts the SAN of the certificate SES SMTP presents, so it verifies.
def _tls_socket(host: str, port: int) -> ssl.SSLSocket:
    """A TLS socket to the SMTP listener, opened by hand so the raw bytes are readable.

    A connect or handshake failure is reported with the data-plane sentinel: it means nothing was
    listening, which is a FIDELITY finding about the target, not an environment error to be
    excluded from the rate.
    """
    try:
        raw = socket.create_connection((host, port), timeout=_CONNECT_TIMEOUT_S)
    except OSError as exc:
        raise AssertionError(
            f"{_DATAPLANE_SENTINEL}: nothing accepted a TCP connection on {host}:{port}; the SES "
            f"SMTP submission data plane is a separate listener from the signed API and this "
            f"target has none ({exc!r})"
        ) from exc
    try:
        sock = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
    except (ssl.SSLError, OSError) as exc:
        raw.close()
        raise AssertionError(
            f"{_DATAPLANE_SENTINEL}: {host}:{port} accepted TCP but did not complete a TLS "
            f"handshake; smtp-connect.html requires every SES SMTP connection to be encrypted "
            f"({exc!r})"
        ) from exc
    sock.settimeout(_CONNECT_TIMEOUT_S)
    return sock


def _delete_user_verified(iam, user: str, policy: str) -> None:
    """A long-lived IAM access key is a real credential, so the teardown is verified rather than
    best-effort. ctx.on_cleanup swallows exceptions, so print the leak before raising."""
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
    """An authenticated session, with a bounded retry on 535 and a deadline that RAISES.

    A freshly minted IAM access key is not immediately usable on every SES SMTP frontend and no API
    reports when it becomes usable — successive connections land on different frontends, so an AUTH
    that succeeded once can still be refused seconds later. The retry is what makes every positive
    leg below correct.
    """
    deadline = time.monotonic() + _AUTH_CONVERGENCE_DEADLINE_S
    last: object = None
    attempts = 0
    while time.monotonic() < deadline:
        attempts += 1
        smtp = smtplib.SMTP_SSL(
            host, port, timeout=_CONNECT_TIMEOUT_S, context=ssl.create_default_context()
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
        f"{_AUTH_CONVERGENCE_DEADLINE_S}s ({attempts} attempts); the last refusal was {last!r}"
    )


def _submit_once(
    host: str,
    port: int,
    access_key_id: str,
    password: str,
    envelope_from: str,
    header_lines: list[str],
) -> tuple[str, int, str]:
    """Walk one SMTP submission and return (phase, code, text) for the FIRST reply that is not an
    advance. A phase-tagged triple, because WHERE SES refuses is as much of the contract as the
    code — measured directly by this file's own baseline leg that an unverified sender is accepted
    at MAIL FROM and RCPT TO and refused only once the body is complete, and a target that refuses
    earlier breaks every client that streams DATA before checking.

    The session is authenticated immediately before use: SES closes an idle authenticated
    connection with `451 4.4.2 Timeout waiting for data from client.`, and a reused session would
    grade that timeout instead of the verdict under test.
    """
    smtp = _authed(host, port, access_key_id, password)
    try:
        code, message = smtp.docmd("MAIL", f"FROM:<{envelope_from}>")
        if code != 250:
            return ("mail-from", code, message.decode("ascii", "replace"))
        code, message = smtp.docmd("RCPT", f"TO:<{_RECIPIENT}>")
        if code != 250:
            return ("rcpt-to", code, message.decode("ascii", "replace"))
        code, message = smtp.docmd("DATA")
        if code != 354:
            return ("data", code, message.decode("ascii", "replace"))
        smtp.send(("\r\n".join(header_lines) + "\r\n\r\nsim2real probe body\r\n.\r\n").encode())
        code, message = smtp.getreply()
        return ("data-end", code, message.decode("ascii", "replace"))
    finally:
        try:
            smtp.quit()
        except smtplib.SMTPException:
            smtp.close()


def _submit(
    host: str,
    port: int,
    access_key_id: str,
    password: str,
    envelope_from: str,
    header_lines: list[str],
) -> tuple[str, int, str]:
    """`_submit_once`, retried on the mid-transaction credential-propagation race: a connection
    that AUTHed successfully (235) can still answer the end-of-DATA reply
    with `535 Authentication Credentials Invalid` if that reply lands on a backend whose view of the
    freshly minted key has not converged yet — the same underlying race `_authed` already retries at
    AUTH time, one step further down the pipeline. Retrying the WHOLE transaction (fresh connection,
    fresh AUTH) is correct because a stale-credential 535 is not a verdict about sender identity.
    """
    deadline = time.monotonic() + _TRANSACTION_RETRY_DEADLINE_S
    while True:
        phase, code, text = _submit_once(
            host, port, access_key_id, password, envelope_from, header_lines
        )
        stale_credential = phase == "data-end" and code == 535 and "Credentials Invalid" in text
        if not stale_credential or time.monotonic() >= deadline:
            return (phase, code, text)
        time.sleep(_TRANSACTION_RETRY_INTERVAL_S)


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:native",
    "plane:data",
)
def run(ctx) -> None:
    """With different unverified addresses in MAIL FROM and the From: header, SES's 554 names exactly
    one of them, chosen by the address pair and not by field role (a swap names the same address),
    and a message with no From: header gets the envelope == header refusal byte for byte."""
    iam = ctx.client("iam")
    ses = ctx.client("ses")
    sesv2 = ctx.client("sesv2")
    host, port = ctx.service_host(f"email-smtp.{ctx.region}.amazonaws.com", _SMTP_PORT)

    # --- the endpoint under test really is SES's SMTP listener, read off the raw socket.
    sock = _tls_socket(host, port)
    try:
        banner = sock.recv(512).decode("ascii", "replace")
        peer_cert = sock.getpeercert()
    finally:
        sock.close()
    assert banner.startswith("220 "), (
        f"the SMTP greeting on {host}:{port} was {banner!r}, expected a 220 line"
    )
    assert "ESMTP SimpleEmailService" in banner, (
        f"the SMTP greeting {banner!r} does not name the SES SMTP server"
    )
    sans = {value for kind, value in peer_cert.get("subjectAltName", ()) if kind == "DNS"}
    assert host in sans, (
        f"the TLS certificate on {host}:{port} has SANs {sorted(sans)!r}, which do not "
        f"include {host!r} — the connection is not terminated by SES"
    )

    # AWS documents that SMTP credentials cannot be derived from temporary credentials, so the
    # check mints a long-lived key of its own rather than reusing the harness session.
    user = ctx.unique_name("sim2real-behav-smtp-fromhdr-")
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

    # Two addresses on two distinct domains, so neither is a substring of the other and "which one
    # did the refusal name" is decidable. Both are unverified, which is the point: the gate is
    # ARMED in every arm and the only variable is which field carries which address.
    domain_a = ctx.unique_name("sim2real-behav-envelope-") + ".example.com"
    domain_b = ctx.unique_name("sim2real-behav-header-") + ".example.com"
    addr_a, addr_b = f"noreply@{domain_a}", f"noreply@{domain_b}"
    assert addr_a not in addr_b and addr_b not in addr_a, (
        f"the two probe addresses must be mutually non-substring for the naming legs to be "
        f"decidable; got {addr_a!r} and {addr_b!r}"
    )

    def _headers(from_address: str | None) -> list[str]:
        lines = [f"To: {_RECIPIENT}", "Subject: sim2real smtp from-header probe"]
        if from_address is not None:
            lines.insert(0, f"From: {from_address}")
        return lines

    def _named_address(text: str) -> str:
        """The ONE probe address the refusal names, read out of the reply text itself rather than
        inferred from which field we put it in. Raises when the reply names both or neither, because
        then the arms below have no subject to compare."""
        hits = [address for address in (addr_a, addr_b) if address in text]
        assert len(hits) == 1, (
            f"the identity refusal must name exactly one of {addr_a!r} and {addr_b!r} so the named "
            f"identity is legible; it named {hits!r}: {text!r}"
        )
        return hits[0]

    stats_before = ses.get_send_statistics()["SendDataPoints"]

    # --- Beat 1, positive control: envelope == header, the baseline refusal. This is
    #     what a correct submission of an unverified sender looks like, and every later arm is
    #     compared against it.
    baseline = _submit(host, port, access_key_id, password, addr_a, _headers(addr_a))
    assert baseline[0] == "data-end", (
        f"SES must defer sender verification to end-of-DATA, accepting MAIL FROM and RCPT TO "
        f"first; the baseline submission was instead refused at phase {baseline[0]!r}: "
        f"{baseline[1]} {baseline[2]!r}"
    )
    assert baseline[1] == 554, (
        f"the baseline end-of-DATA reply for an unverified sender must be 554; got {baseline[1]} "
        f"{baseline[2]!r}"
    )
    assert baseline[2].startswith(
        "Message rejected: Email address is not verified. The following identities failed the "
        f"check in region {ctx.region.upper()}: "
    ), (
        f"the baseline refusal must be the identity gate's MEASURED, region-qualified payload "
        f"shape, so the later arms are compared against the right thing; got {baseline[2]!r}"
    )

    # --- Beat 2, break exactly one thing: put a DIFFERENT unverified address in the From header.
    #     Nothing else changes — same envelope, same recipient, same body.
    split_ab = _submit(host, port, access_key_id, password, addr_a, _headers(addr_b))
    assert (split_ab[0], split_ab[1]) == ("data-end", 554), (
        f"a submission whose envelope and From header are two different unverified addresses must "
        f"still be refused 554 at end-of-DATA; got {split_ab!r}"
    )
    named_ab = _named_address(split_ab[2])

    # --- Beat 3, swap the two addresses between the two fields. Nothing else changes. This is the
    #     leg that turns the verdict into a MEASUREMENT rather than a guess.
    #
    #     The address the 554 names does NOT flip when you swap which field carries it. It is
    #     a function of the unordered pair {addr_a, addr_b}, not of role — one trial named the
    #     header's address going one way and the (now different) envelope's address going the other
    #     way, for the SAME literal winning address both times. Neither "envelope always" nor
    #     "header always" survives that; only role-independence does.
    split_ba = _submit(host, port, access_key_id, password, addr_b, _headers(addr_a))
    assert (split_ba[0], split_ba[1]) == ("data-end", 554), (
        f"the swapped submission must also be refused 554 at end-of-DATA; got {split_ba!r}"
    )
    named_ba = _named_address(split_ba[2])

    # The measured invariant: swapping which field carries which address must NOT change which one
    # is named. A target that decides by role — envelope-always or header-always alike — fails here,
    # which is exactly the class of emulator bug this file exists to catch.
    assert named_ab == named_ba, (
        f"the address the 554 names must be invariant under swapping which SMTP field carries it — "
        f"real SES's selection is a function of the pair {{{addr_a!r}, {addr_b!r}}}, not of role; "
        f"putting {addr_b!r} in the header named {named_ab!r}, and putting it in the envelope "
        f"instead (with {addr_a!r} now in the header) named {named_ba!r}. Replies were "
        f"{split_ab[2]!r} and {split_ba[2]!r}"
    )

    # --- Beat 4, effect absent: neither refused submission created an identity, read at the
    #     destination through a different API than the one that would have created it.
    for domain in (domain_a, domain_b):
        try:
            identity = sesv2.get_email_identity(EmailIdentity=domain)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            assert code == "NotFoundException", (
                f"GetEmailIdentity for the refused domain {domain!r} raised {code!r}, expected "
                f"'NotFoundException'"
            )
            msg = exc.response.get("Error", {}).get("Message")
            expected_msg = f"Email identity <{domain}> does not exist."
            assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"
        else:
            raise AssertionError(
                f"GetEmailIdentity returned {identity.get('IdentityType')!r} for {domain!r} — a "
                f"refused submission must not create an identity"
            )

    # --- Beat 5, remove the From: header entirely. Real SES falls back
    #     to the envelope address as the identity to check and answers the EXACT SAME 554 as the
    #     baseline (envelope == header == addr_a) — i.e. the envelope is not inert; it is the
    #     fallback identity source when there is no From: header to read at all.
    headerless = _submit(host, port, access_key_id, password, addr_a, _headers(None))
    assert headerless == baseline, (
        f"with no From: header, SES's identity gate must fall back to the envelope address and "
        f"answer the identical verdict it gives when envelope == header == {addr_a!r}; expected "
        f"{baseline!r}, got {headerless!r}"
    )

    # --- Beat 6, restore: put the From header back and the identical baseline submission is
    #     refused identically again. The missing header was the only thing that had changed.
    restored = _submit(host, port, access_key_id, password, addr_a, _headers(addr_a))
    assert restored == baseline, (
        f"restoring the From: header must return the identical baseline verdict; expected "
        f"{baseline!r}, got {restored!r}"
    )

    # --- An independent side-channel: five refusals, no delivery attempts.
    stats_after = ses.get_send_statistics()["SendDataPoints"]
    assert stats_after == stats_before, (
        f"GetSendStatistics moved from {stats_before!r} to {stats_after!r} across five refused "
        f"submissions; a refused message must never be counted as a delivery attempt"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
