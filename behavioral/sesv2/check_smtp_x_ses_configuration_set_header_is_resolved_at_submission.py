"""smtp-x-ses-configuration-set-header-is-resolved-at-submission."""
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

CHECK = "smtp-x-ses-configuration-set-header-is-resolved-at-submission"
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
#: The header SES documents for selecting a configuration set on the SMTP interface and SendRawEmail:
#: https://docs.aws.amazon.com/ses/latest/dg/using-configuration-sets-in-email.html — "If you are
#: using the SMTP interface or the SendRawEmail API operation, you can specify a configuration set by
#: including the following header in your email: X-SES-CONFIGURATION-SET: ConfigSet".
_HEADER = "X-SES-CONFIGURATION-SET"

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
    """SES resolves the X-SES-CONFIGURATION-SET header at SMTP submission: a missing set changes the
    verdict and the refusal names it, an existing set restores the identity-gate verdict byte for
    byte, the header name matches case-insensitively, and refused submissions create nothing."""
    iam = ctx.client("iam")
    ses = ctx.client("ses")
    sesv2 = ctx.client("sesv2")
    host, port = ctx.service_host(f"email-smtp.{ctx.region}.amazonaws.com", _SMTP_PORT)

    assert sesv2.get_account()["SendingEnabled"] is True, (
        "setup precondition: account-level sending must be ENABLED, or a changed SMTP verdict cannot "
        "be attributed to the configuration-set header; GetAccount reported SendingEnabled false"
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

    # --- the real configuration set, created in-check through the v2 API and confirmed by an
    #     independent read. quotas.html caps a configuration-set name at 64 alphanumeric characters
    #     plus - and _, which ctx.unique_name satisfies.
    real_set = ctx.unique_name("sim2real-behav-smtp-cs-")
    sesv2.create_configuration_set(
        ConfigurationSetName=real_set, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: sesv2.delete_configuration_set(ConfigurationSetName=real_set))
    assert (
        sesv2.get_configuration_set(ConfigurationSetName=real_set)["ConfigurationSetName"]
        == real_set
    ), (
        f"setup precondition: the configuration set {real_set!r} must exist before the positive "
        f"control names it"
    )
    ghost_set = ctx.unique_name("sim2real-behav-smtp-ghost-")
    try:
        existing = sesv2.get_configuration_set(ConfigurationSetName=ghost_set)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        assert code == "NotFoundException", (
            f"setup precondition: GetConfigurationSet for the ghost name {ghost_set!r} must raise "
            f"NotFoundException; raised {code!r}"
        )
        msg = exc.response.get("Error", {}).get("Message")
        expected_msg = f"Configuration set <{ghost_set}> does not exist."
        assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"
    else:
        raise AssertionError(
            f"the ghost configuration-set name {ghost_set!r} already exists ({existing!r}); the "
            f"negative arm needs a name that is genuinely absent"
        )

    # AWS documents that SMTP credentials cannot be derived from temporary credentials, so the check
    # mints a long-lived key of its own rather than reusing the harness session.
    user = ctx.unique_name("sim2real-behav-smtp-cshdr-")
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

    sender = f"noreply@{ctx.unique_name('sim2real-behav-cshdr-')}.example.com"
    stats_before = ses.get_send_statistics()["SendDataPoints"]

    def _submit(header_name: str | None, configuration_set: str | None) -> tuple[str, int, str]:
        """One submission, optionally carrying the configuration-set header. Returns
        (phase, code, text) for the first reply that is not an advance — the PHASE is part of the
        verdict because where SES resolves the header is exactly what is undocumented.

        The session is authenticated immediately before use: SES closes an idle authenticated
        connection with `451 4.4.2 Timeout waiting for data from client.`, and a reused session would
        grade that timeout instead of the verdict under test.
        """
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
            lines = []
            if header_name is not None and configuration_set is not None:
                lines.append(f"{header_name}: {configuration_set}")
            lines += [
                f"From: {sender}",
                f"To: {_RECIPIENT}",
                "Subject: sim2real smtp configuration-set header probe",
            ]
            smtp.send(("\r\n".join(lines) + "\r\n\r\nprobe body\r\n.\r\n").encode())
            code, message = smtp.getreply()
            return ("data-end", code, message.decode("ascii", "replace"))
        finally:
            try:
                smtp.quit()
            except smtplib.SMTPException:
                smtp.close()

    # --- Beat 1, positive control: no header at all. This is the reference verdict every other arm is
    #     measured against.
    baseline = _submit(None, None)
    assert baseline[0] == "data-end", (
        f"with no configuration-set header the submission must reach end-of-DATA; it was refused at "
        f"phase {baseline[0]!r}: {baseline[1]} {baseline[2]!r}"
    )
    assert baseline[1] == 554, (
        f"the header-free baseline must be the identity gate's 554; got {baseline[1]} {baseline[2]!r}"
    )
    assert baseline[2].startswith("Message rejected: Email address is not verified."), (
        f"the baseline must terminate on the IDENTITY gate, so the header arms are compared against "
        f"the right thing; got {baseline[2]!r}"
    )

    # --- Beat 2, positive control for the header ITSELF: naming a configuration set that exists must
    #     leave the verdict exactly as it was. This is what proves Beat 3's difference is about the
    #     set being missing and not about the presence of an X-header.
    with_real = _submit(_HEADER, real_set)
    assert with_real == baseline, (
        f"naming the existing configuration set {real_set!r} must leave the verdict identical to the "
        f"header-free baseline {baseline!r} — the header is accepted and the unverified sender is the "
        f"only remaining fault; got {with_real!r}"
    )

    # --- Beat 3, break exactly one thing: the same header, a configuration set that does not exist.
    with_ghost = _submit(_HEADER, ghost_set)
    assert with_ghost != baseline, (
        f"naming the nonexistent configuration set {ghost_set!r} drew the identical verdict to the "
        f"header-free baseline {baseline!r}; SES is not resolving the {_HEADER} header at all, which "
        f"means no configuration set's event destinations, IP pool or TLS policy is applied to an "
        f"SMTP-submitted message"
    )
    assert with_ghost[1] >= 500, (
        f"an unresolvable configuration set must draw a permanent refusal; got {with_ghost!r}"
    )
    assert ghost_set in with_ghost[2], (
        f"the refusal must NAME the configuration set it could not find, {ghost_set!r} — that is what "
        f"proves the header was parsed rather than pattern-matched, and it is what the API-side "
        f"incumbent behavioral/ses/check_send_raw_email_unknown_configuration_set_fails.py asserts "
        f"for the equivalent parameter; got {with_ghost[2]!r}"
    )

    # --- Beat 4, effect absent, read at the destination through operations that did not submit
    #     anything: the refused submission created no configuration set, and the real one gained no
    #     event destination.
    try:
        created = sesv2.get_configuration_set(ConfigurationSetName=ghost_set)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        assert code == "NotFoundException", (
            f"GetConfigurationSet for the ghost name after the refusal raised {code!r}, expected "
            f"'NotFoundException'"
        )
        msg = exc.response.get("Error", {}).get("Message")
        expected_msg = f"Configuration set <{ghost_set}> does not exist."
        assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"
    else:
        raise AssertionError(
            f"GetConfigurationSet now returns {created!r} for {ghost_set!r} — a refused submission "
            f"must not create the configuration set it named"
        )
    # `.get(..., [])` is the sanctioned polarity here: the empty default feeds `assert not`, so a
    # missing key produces the PASSING-shaped value only for the claim "there are none", which is the
    # claim being made. SESv2 omits the key entirely when the list is empty.
    destinations = sesv2.get_configuration_set_event_destinations(
        ConfigurationSetName=real_set
    ).get("EventDestinations", [])
    assert not destinations, (
        f"the configuration set this check created must still have no event destinations; got "
        f"{destinations!r}"
    )

    # --- Beat 5, the header NAME is a header name: RFC 5322 s1.2.2 makes field names
    #     case-insensitive, so a lower-cased spelling must behave identically in BOTH directions. Two
    #     arms, because one alone cannot tell "matches case-insensitively" from "matches nothing".
    lower_real = _submit(_HEADER.lower(), real_set)
    assert lower_real == baseline, (
        f"a lower-cased {_HEADER.lower()!r} naming the existing set must behave identically to the "
        f"documented spelling; expected {baseline!r}, got {lower_real!r}"
    )
    lower_ghost = _submit(_HEADER.lower(), ghost_set)
    assert lower_ghost == with_ghost, (
        f"a lower-cased {_HEADER.lower()!r} naming the nonexistent set must draw the identical "
        f"refusal as the upper-case spelling — RFC 5322 field names are case-insensitive; expected "
        f"{with_ghost!r}, got {lower_ghost!r}"
    )

    # --- Beat 6, restore, and the terminal read: the identical header-free submission is refused
    #     identically again, and the configuration set this check created is still there and intact.
    restored = _submit(None, None)
    assert restored == baseline, (
        f"the identical header-free submission must draw the identical verdict after four header "
        f"probes; expected {baseline!r}, got {restored!r}"
    )
    final = sesv2.get_configuration_set(ConfigurationSetName=real_set)
    assert final["ConfigurationSetName"] == real_set, (
        f"the configuration set this check created must still be readable under its own name; "
        f"GetConfigurationSet returned {final!r}"
    )

    # --- An independent side-channel: five refusals, no delivery attempts.
    stats_after = ses.get_send_statistics()["SendDataPoints"]
    assert stats_after == stats_before, (
        f"GetSendStatistics moved from {stats_before!r} to {stats_after!r}; every submission here was "
        f"refused and none may count as a delivery attempt"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
