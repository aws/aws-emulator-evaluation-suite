"""smtp-derived-credential-authenticates-and-a-wrong-region-derivation-is-rejected."""
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

# Everything here is stdlib. No AWS API call takes part in the SMTP exchange at all, which is the
# point of the check: the credential is a keyed hash of a secret the server must also hold, and
# the region is INSIDE the hash rather than in a header a recorder could echo.
#
# Every response code and message string asserted below was measured against real SES in us-west-2.
#
# PORT: this check speaks IMPLICIT TLS on 465 (RFC 8314 "smtps"), not STARTTLS on 587. Measured
# on the authoring host: a TCP connect to email-smtp.us-west-2.amazonaws.com succeeds on 465 and
# times out on 25, 587, 2465 and 2587 in the same second -- egress filtering, not SES. 465 is a
# documented SES SMTP port and carries the identical credential algebra, so the derivation
# assertions are unaffected; the RFC 3207 STARTTLS upgrade itself is simply not gradeable from
# here and is not asserted rather than asserted weakly.

_SMTP_PORT = 465
# The SMTP password derivation SES documents: a SigV4 signing chain over a FIXED date, keyed on
# the region and on the literal service name "ses" and terminal string "SendRawEmail", with a
# one-byte version prefix. https://docs.aws.amazon.com/ses/latest/dg/smtp-credentials.html
_DERIVE_DATE = "11111111"
_DERIVE_SERVICE = "ses"
_DERIVE_TERMINAL = "SendRawEmail"
_DERIVE_VERSION = 0x04
# The mailbox simulator: a real deliverable recipient that never leaves SES, so the check can
# reach end-of-DATA without mailing a human. The account is in the SES sandbox, so the SENDER is
# what gets refused, which is exactly the arm this check wants.
_RECIPIENT = "success@simulator.amazonses.com"


def _smtp_password(secret_access_key, region):
    """base64(0x04 || HMAC-chain) -- the SES SMTP password derived from an IAM secret key."""
    def _sign(key, msg):
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    signature = _sign(("AWS4" + secret_access_key).encode("utf-8"), _DERIVE_DATE)
    for element in (region, _DERIVE_SERVICE, "aws4_request", _DERIVE_TERMINAL):
        signature = _sign(signature, element)
    return base64.b64encode(bytes([_DERIVE_VERSION]) + signature).decode("ascii")


def _delete_user_verified(iam, user, policy):
    """A long-lived IAM access key is a real credential: the teardown is verified, not
    best-effort. ctx.on_cleanup swallows exceptions, so print before raising."""
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


# tls-subject: the check asserts the SAN of the certificate SES SMTP presents, so it verifies.
def _greeting(host, port, timeout=30):
    """Read the raw 220 line off the TLS socket. smtplib.SMTP_SSL consumes the greeting into its
    own reply tuple and discards the text, so the banner is read directly."""
    context = ssl.create_default_context()
    sock = context.wrap_socket(
        socket.create_connection((host, port), timeout=timeout), server_hostname=host
    )
    try:
        sock.settimeout(timeout)
        return sock.recv(512).decode("ascii", "replace"), sock.getpeercert()
    finally:
        sock.close()


def _session(host, port, timeout=30):
    smtp = smtplib.SMTP_SSL(host, port, timeout=timeout, context=ssl.create_default_context())
    smtp.ehlo()
    return smtp


def _authed(host, port, access_key_id, password, attempts=30, delay=5.0):
    """Open a session and AUTH, with a bounded retry on 535.

    A freshly minted IAM access key is not immediately usable on every SES SMTP frontend, and no
    API reports when it becomes usable -- successive connections land on different frontends, so
    an AUTH that succeeded once can still be refused on the next connection for a few seconds.
    The retry is what makes the positive arms correct; the negative arms below get NO retry,
    because for them a 535 is the answer."""
    last = None
    for _ in range(attempts):
        smtp = _session(host, port)
        try:
            code, message = smtp.login(access_key_id, password)
        except smtplib.SMTPAuthenticationError as exc:
            last = (exc.smtp_code, exc.smtp_error)
            smtp.close()
            time.sleep(delay)
            continue
        return smtp, code, message
    raise AssertionError(
        f"the correctly derived SMTP password never authenticated on {host}:{port} in "
        f"{attempts} attempts; the last refusal was {last!r}"
    )


def _refused(host, port, access_key_id, password):
    """AUTH with a deliberately wrong derivation; return (code, error) or raise if it succeeded."""
    smtp = _session(host, port)
    try:
        smtp.login(access_key_id, password)
    except smtplib.SMTPAuthenticationError as exc:
        return exc.smtp_code, exc.smtp_error
    finally:
        smtp.close()
    raise AssertionError(
        "AUTH with a deliberately wrong derivation was ACCEPTED -- the mutated element is not "
        "part of the credential this endpoint verifies"
    )


CHECK = "smtp-derived-credential-authenticates-and-a-wrong-region-derivation-is-rejected"
GROUP = 'rejected'
SERVICES = ['ses']


@tags("axis:rejection", "cap:c1", "cap:c6", "concern:data-plane", "concern:negative-classes",
      "dp:native", "plane:data")
def run(ctx) -> None:
    """The SES SMTP endpoint authenticates the region-keyed derived credential with 235 and refuses one
    derived for another region, service or version byte with 535 "Authentication Credentials
    Invalid"; an unverified sender is refused at end-of-DATA with 554, leaving no identity behind."""
    iam = ctx.client("iam")
    ses = ctx.client("ses")
    sesv2 = ctx.client("sesv2")
    host, port = ctx.service_host(f"email-smtp.{ctx.region}.amazonaws.com", _SMTP_PORT)

    # AWS documents that temporary credentials cannot be used to derive SMTP credentials, so the
    # check mints a long-lived key of its own rather than reusing the harness session.
    user = ctx.unique_name("sim2real-behav-ses-smtp-")
    policy = "sim2real-ses-send-raw-email"
    iam.create_user(UserName=user, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_user_verified(iam, user, policy))
    iam.put_user_policy(
        UserName=user,
        PolicyName=policy,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["ses:SendRawEmail"], "Resource": "*"}],
        }),
    )
    key = iam.create_access_key(UserName=user)["AccessKey"]
    access_key_id, secret = key["AccessKeyId"], key["SecretAccessKey"]

    # --- the derivation is a protocol constant, checked in-process before any socket opens ---
    password = _smtp_password(secret, ctx.region)
    decoded = base64.b64decode(password)
    assert len(decoded) == 33, (
        f"the derived SMTP password decodes to {len(decoded)} bytes, expected 33 "
        f"(one version byte + a SHA-256 HMAC)"
    )
    assert decoded[0] == _DERIVE_VERSION, (
        f"the derived SMTP password's version byte is {decoded[0]:#04x}, expected 0x04"
    )

    # --- the greeting and the certificate: a real SES SMTP listener, not a plaintext echo ---
    banner, cert = _greeting(host, port)
    assert banner.startswith("220 "), f"the SMTP greeting was {banner!r}, expected a 220 line"
    assert "ESMTP SimpleEmailService" in banner, (
        f"the SMTP greeting {banner!r} does not name the SES SMTP server"
    )
    sans = {value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"}
    assert host in sans, (
        f"the TLS certificate on {host}:{port} has SANs {sorted(sans)!r}, which do not "
        f"include {host!r} -- the connection is not terminated by SES"
    )

    # --- the TLS listener offers exactly the RFC 4954 mechanisms SES documents ---
    probe = _session(host, port)
    try:
        assert "auth" in probe.esmtp_features, (
            f"EHLO advertised {sorted(probe.esmtp_features)!r}, with no AUTH -- SES must offer "
            f"authentication on the TLS listener"
        )
        assert set(probe.esmtp_features["auth"].split()) == {"PLAIN", "LOGIN"}, (
            f"EHLO advertised AUTH {probe.esmtp_features['auth']!r}, expected exactly PLAIN "
            f"and LOGIN"
        )
        # Effect-absent for an unauthenticated session: MAIL FROM is refused outright.
        anon_code, anon_message = probe.docmd("MAIL", f"FROM:<{access_key_id}@example.invalid>")
        assert anon_code == 530, (
            f"MAIL FROM on an unauthenticated session answered {anon_code} {anon_message!r}, "
            f"expected 530"
        )
        assert anon_message == b"Authentication required", (
            f"the unauthenticated MAIL FROM message was {anon_message!r}, expected "
            f"b'Authentication required'"
        )
    finally:
        probe.close()

    # --- authentication: the correct derivation is accepted ---
    smtp, code, message = _authed(host, port, access_key_id, password)
    smtp.close()
    assert (code, message) == (235, b"Authentication successful."), (
        f"AUTH with the correctly derived password answered {(code, message)!r}, expected "
        f"(235, b'Authentication successful.')"
    )

    # --- negatives: every element of the derivation is load-bearing ---
    # The region arm is the unfakeable one. The region is inside the HMAC chain, so an emulator
    # that accepts any password, or that authenticates the access key id alone, passes a
    # credential that real SES refuses -- and the production deploy then fails auth in a region
    # CI approved. The service name and the version byte are checked the same way, and each
    # negative is followed IMMEDIATELY by the correct password on a fresh connection, so a 535
    # can never be a propagation artifact standing in for a refusal.
    def _mutated(region=None, service=None, terminal=None, version=None):
        def _sign(k, m):
            return hmac.new(k, m.encode("utf-8"), hashlib.sha256).digest()
        sig = _sign(("AWS4" + secret).encode("utf-8"), _DERIVE_DATE)
        for element in (region or ctx.region, service or _DERIVE_SERVICE, "aws4_request",
                        terminal or _DERIVE_TERMINAL):
            sig = _sign(sig, element)
        return base64.b64encode(
            bytes([_DERIVE_VERSION if version is None else version]) + sig
        ).decode("ascii")

    other_region = "us-east-1" if ctx.region != "us-east-1" else "us-west-2"
    for label, mutated in (
        (f"region={other_region!r}", _mutated(region=other_region)),
        ("service='sesv2'", _mutated(service="sesv2")),
        ("terminal='SendEmail'", _mutated(terminal="SendEmail")),
        ("version=0x03", _mutated(version=0x03)),
    ):
        assert mutated != password, (
            f"mutating {label} produced the same password as the correct derivation; that "
            f"element is not entering the HMAC chain at all"
        )
        bad_code, bad_error = _refused(host, port, access_key_id, mutated)
        assert bad_code == 535, (
            f"a password derived with {label} was refused with {bad_code} {bad_error!r}, "
            f"expected 535"
        )
        assert bad_error == b"Authentication Credentials Invalid", (
            f"the {label} refusal message was {bad_error!r}, expected "
            f"b'Authentication Credentials Invalid'"
        )
        # Positive control: same key, same endpoint, next connection.
        control, control_code, control_message = _authed(
            host, port, access_key_id, password
        )
        control.close()
        assert (control_code, control_message) == (235, b"Authentication successful."), (
            f"the control login after the {label} refusal answered "
            f"{(control_code, control_message)!r}, expected (235, b'Authentication successful.')"
        )

    # --- an unverified sender is refused at end-of-DATA, not at MAIL FROM ---
    sender_domain = ctx.unique_name("sim2real-behav-unverified-") + ".example.com"
    sender = f"noreply@{sender_domain}"
    stats_before = ses.get_send_statistics()["SendDataPoints"]
    # A session authenticated immediately before use: SES closes an idle authenticated connection
    # with `451 4.4.2 Timeout waiting for data from client.`, and an earlier session reused here
    # would grade that timeout instead of the sender refusal.
    smtp, send_code, send_message = _authed(host, port, access_key_id, password)
    assert (send_code, send_message) == (235, b"Authentication successful."), (
        f"the sending session's login answered {(send_code, send_message)!r}, expected "
        f"(235, b'Authentication successful.')"
    )
    # Measured: SES accepts MAIL FROM and RCPT TO for an unverified sender and refuses only once
    # the message body is complete. Asserting the phase is the property -- an emulator that
    # refuses at MAIL FROM breaks every client that streams DATA before checking.
    mail_code, mail_message = smtp.docmd("MAIL", f"FROM:<{sender}>")
    assert (mail_code, mail_message) == (250, b"Ok"), (
        f"MAIL FROM for the unverified sender {sender!r} answered {(mail_code, mail_message)!r}, "
        f"expected (250, b'Ok') -- SES defers sender verification to end-of-DATA"
    )
    rcpt_code, rcpt_message = smtp.docmd("RCPT", f"TO:<{_RECIPIENT}>")
    assert (rcpt_code, rcpt_message) == (250, b"Ok"), (
        f"RCPT TO {_RECIPIENT!r} answered {(rcpt_code, rcpt_message)!r}, expected (250, b'Ok')"
    )
    data_code, data_message = smtp.docmd("DATA")
    assert data_code == 354, (
        f"DATA answered {data_code} {data_message!r}, expected 354"
    )
    smtp.send(
        f"From: {sender}\r\nTo: {_RECIPIENT}\r\n"
        f"Subject: sim2real behavioral probe\r\n\r\nunverified sender probe\r\n.\r\n".encode()
    )
    end_code, end_message = smtp.getreply()
    assert end_code == 554, (
        f"end-of-DATA for the unverified sender answered {end_code} {end_message!r}, expected 554"
    )
    text = end_message.decode("ascii", "replace")
    assert text.startswith("Message rejected: Email address is not verified."), (
        f"the unverified-sender refusal was {text!r}, expected it to open with "
        f"'Message rejected: Email address is not verified.'"
    )
    assert sender in text and ctx.region.upper() in text, (
        f"the unverified-sender refusal {text!r} names neither the sender {sender!r} nor the "
        f"region {ctx.region.upper()!r} that failed the check"
    )
    try:
        smtp.quit()
    except smtplib.SMTPException:
        smtp.close()

    # Effect-absent: the refusal produced no delivery attempt and created no identity.
    stats_after = ses.get_send_statistics()["SendDataPoints"]
    assert stats_after == stats_before, (
        f"GetSendStatistics moved from {stats_before!r} to {stats_after!r} across a 554 refusal; "
        f"a rejected message must not be counted as a delivery attempt"
    )
    try:
        identity = sesv2.get_email_identity(EmailIdentity=sender_domain)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message2 = exc.response.get("Error", {}).get("Message")
        assert code == "NotFoundException", (
            f"GetEmailIdentity for the refused sender domain raised {code!r}, expected "
            f"'NotFoundException'"
        )
        assert message2 == f"Email identity <{sender_domain}> does not exist.", (
            f"expected the exact NotFoundException message AWS returns, got {message2!r}"
        )
    else:
        raise AssertionError(
            f"GetEmailIdentity returned {identity.get('IdentityType')!r} for "
            f"{sender_domain!r} -- the refused send must not have created an identity"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
