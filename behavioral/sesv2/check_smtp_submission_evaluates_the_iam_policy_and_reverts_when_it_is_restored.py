"""smtp-submission-evaluates-the-iam-policy-and-reverts-when-it-is-restored."""
# A '554 Access denied' for an SMTP user without ses:SendRawEmail is documented
# (repost.aws/knowledge-center/amazon-ses-iam-user-email-access-denied); its exact text is not.
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

CHECK = "smtp-submission-evaluates-the-iam-policy-and-reverts-when-it-is-restored"
GROUP = "rejected"
SERVICES = ["sesv2"]

# ===== helpers =====
# The banner is read through a raw TLS socket because smtplib discards the greeting text.

_SMTP_PORT = 465  # implicit TLS ("TLS Wrapper", smtp-connect.html); the only port the runner reaches
_CONNECT_TIMEOUT_S = 30.0
#: Convergence of a freshly minted IAM access key on the SMTP frontends. Raises, never sleeps.
_AUTH_CONVERGENCE_DEADLINE_S = 150.0
#: How long the revoked policy may take to reach the SMTP frontends. Bounded; raises on timeout.
_REVOKE_PROPAGATION_DEADLINE_S = 180.0
#: How long the RE-GRANTED policy may take. Larger than the revoke budget on purpose: the frontends
#: that answered a denial may hold that decision, and this is the leg that proves the control is
#: two-sided rather than a one-way trapdoor.
_RESTORE_PROPAGATION_DEADLINE_S = 240.0
_POLL_INTERVAL_S = 10.0
_AUTH_RETRY_INTERVAL_S = 5.0

# https://docs.aws.amazon.com/ses/latest/dg/smtp-credentials.html
_DERIVE_DATE = "11111111"
_DERIVE_SERVICE = "ses"
_DERIVE_TERMINAL = "SendRawEmail"
_DERIVE_VERSION = 0x04

_RECIPIENT = "success@simulator.amazonses.com"
#: Substrings that make a refusal attributable to AUTHORIZATION rather than to anything else. Kept
#: as a class, not a literal: the exact SES wording is undocumented.
_AUTHORIZATION_MARKERS = ("denied", "not authorized", "accessdenied")

_DATAPLANE_SENTINEL = "DATAPLANE_UNIMPLEMENTED"

_SEND_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": ["ses:SendRawEmail"], "Resource": "*"}],
}


def _smtp_password(secret_access_key: str, region: str) -> str:
    """base64(0x04 || HMAC-chain) — the SES SMTP password derived from an IAM secret key."""

    def _sign(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    signature = _sign(("AWS4" + secret_access_key).encode("utf-8"), _DERIVE_DATE)
    for element in (region, _DERIVE_SERVICE, "aws4_request", _DERIVE_TERMINAL):
        signature = _sign(signature, element)
    return base64.b64encode(bytes([_DERIVE_VERSION]) + signature).decode("ascii")


def _tls_socket(host: str, port: int) -> ssl.SSLSocket:
    """A hand-rolled TLS socket to the SMTP listener. A connect or handshake failure carries the
    data-plane sentinel: nothing listening is a fidelity finding about the target, not an
    environment error to be excluded from the published rate."""
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
        try:
            iam.delete_user_policy(UserName=user, PolicyName=policy)
        except ClientError as exc:
            # The check itself may have left the policy deleted if it failed mid-run; a user with no
            # inline policy is still deletable, and any other code is a real teardown failure.
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise
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


def _session(host: str, port: int) -> smtplib.SMTP_SSL:
    smtp = smtplib.SMTP_SSL(
        host, port, timeout=_CONNECT_TIMEOUT_S, context=ssl._create_unverified_context()
    )
    smtp.ehlo()
    return smtp


def _auth_once(host: str, port: int, access_key_id: str, password: str):
    """(smtp, code, message) on acceptance; (None, code, message) on refusal. No retry — used once
    the key is known to have converged, so a 535 is an ANSWER rather than an artifact."""
    smtp = _session(host, port)
    try:
        code, message = smtp.login(access_key_id, password)
    except smtplib.SMTPAuthenticationError as exc:
        smtp.close()
        return None, exc.smtp_code, exc.smtp_error
    return smtp, code, message


def _authed(host: str, port: int, access_key_id: str, password: str) -> smtplib.SMTP_SSL:
    """An authenticated session, with a bounded convergence retry that RAISES on the deadline. Used
    only for the FIRST submission: a freshly minted IAM access key is not immediately usable on every
    SES SMTP frontend and no API reports when it becomes usable."""
    deadline = time.monotonic() + _AUTH_CONVERGENCE_DEADLINE_S
    last: object = None
    attempts = 0
    while time.monotonic() < deadline:
        attempts += 1
        smtp, code, message = _auth_once(host, port, access_key_id, password)
        if smtp is not None:
            assert (code, message) == (235, b"Authentication successful."), (
                f"AUTH with the correctly derived password answered {(code, message)!r}, expected "
                f"(235, b'Authentication successful.')"
            )
            return smtp
        last = (code, message)
        time.sleep(_AUTH_RETRY_INTERVAL_S)
    raise AssertionError(
        f"the correctly derived SMTP password never authenticated on {host}:{port} within "
        f"{_AUTH_CONVERGENCE_DEADLINE_S}s ({attempts} attempts); last refusal {last!r}"
    )


def _submit(
    host: str, port: int, access_key_id: str, password: str, sender: str, *, converge_auth: bool
) -> tuple[str, int, str]:
    """Walk one SMTP submission and return (phase, code, text) for the first reply that is not an
    advance. The PHASE is part of the verdict because where SES refuses is not documented, and a
    triple compares correctly whether the refusal lands at AUTH, at MAIL FROM or at end-of-DATA.

    `converge_auth=True` retries a 535 to the AUTH convergence deadline — right for the baseline,
    where a 535 can only be key propagation. `converge_auth=False` reports the 535 as the verdict —
    right after the baseline has already proved the key works, where a 535 may be the answer.

    The session is authenticated immediately before use: SES closes an idle authenticated connection
    with `451 4.4.2 Timeout waiting for data from client.`, and a reused session would grade that
    timeout instead of the verdict under test.
    """
    if converge_auth:
        smtp = _authed(host, port, access_key_id, password)
    else:
        smtp, code, message = _auth_once(host, port, access_key_id, password)
        if smtp is None:
            return ("auth", code, message.decode("ascii", "replace"))
        assert (code, message) == (235, b"Authentication successful."), (
            f"a successful AUTH answered {(code, message)!r}, expected "
            f"(235, b'Authentication successful.')"
        )
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
        smtp.send(
            f"From: {sender}\r\nTo: {_RECIPIENT}\r\n"
            f"Subject: sim2real smtp authorization probe\r\n\r\nprobe body\r\n.\r\n".encode()
        )
        code, message = smtp.getreply()
        return ("data-end", code, message.decode("ascii", "replace"))
    finally:
        try:
            smtp.quit()
        except smtplib.SMTPException:
            smtp.close()


def _poll_until_verdict(
    predicate,
    deadline_s: float,
    host: str,
    port: int,
    key_id: str,
    password: str,
    sender: str,
    reason: str,
) -> tuple[str, int, str]:
    """Resubmit until the verdict satisfies *predicate*, or RAISE at the deadline naming the last
    verdict seen. Never returns its last value on timeout — a poll that does is how a propagation
    delay gets recorded as a fidelity verdict."""
    deadline = time.monotonic() + deadline_s
    seen: list[tuple[str, int, str]] = []
    while time.monotonic() < deadline:
        verdict = _submit(host, port, key_id, password, sender, converge_auth=False)
        seen.append(verdict)
        if predicate(verdict):
            return verdict
        time.sleep(_POLL_INTERVAL_S)  # fixed-wait: paces resubmission while IAM policy propagates, not a time semantic
    raise AssertionError(
        f"{reason} did not happen within {deadline_s}s; the {len(seen)} verdict(s) observed were "
        f"{seen[-3:]!r} (most recent last)"
    )


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:native", "plane:data")
def run(ctx) -> None:
    """SES's SMTP front door evaluates the submitting IAM user's policy: revoking ses:SendRawEmail
    turns the unverified-sender refusal into an authorization refusal, the revocation is visible in
    IAM, and restoring the identical policy returns the identical original verdict."""
    iam = ctx.client("iam")
    ses = ctx.client("ses")
    sesv2 = ctx.client("sesv2")
    host, port = ctx.service_host(f"email-smtp.{ctx.region}.amazonaws.com", _SMTP_PORT)

    # Rule out an account-level pause: it would also change the reply, for a reason that has nothing
    # to do with the IAM policy under test.
    assert sesv2.get_account()["SendingEnabled"] is True, (
        "setup precondition: account-level sending must be ENABLED, or a changed SMTP verdict cannot "
        "be attributed to the IAM policy; GetAccount reported SendingEnabled false"
    )

    # The listener under test really is SES's, read off the raw socket before anything is asked of it.
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
    # mints its own long-lived key — which is also what makes the policy under test this check's own
    # rather than the harness principal's.
    user = ctx.unique_name("sim2real-behav-smtp-authz-")
    policy = "sim2real-ses-send-raw-email"
    iam.create_user(UserName=user, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_user_verified(iam, user, policy))
    iam.put_user_policy(
        UserName=user, PolicyName=policy, PolicyDocument=json.dumps(_SEND_POLICY)
    )
    key = iam.create_access_key(UserName=user)["AccessKey"]
    access_key_id, secret = key["AccessKeyId"], key["SecretAccessKey"]
    password = _smtp_password(secret, ctx.region)
    sender = f"noreply@{ctx.unique_name('sim2real-behav-authz-')}.example.com"
    stats_before = ses.get_send_statistics()["SendDataPoints"]

    # --- Beat 1, positive control: with the policy in place the submission reaches the identity
    #     gate. This is the ONLY submission allowed to retry a 535, and once it has succeeded the
    #     access key is known to have converged on the frontends — which is what makes a later 535
    #     interpretable as an authorization answer rather than propagation noise.
    baseline = _submit(host, port, access_key_id, password, sender, converge_auth=True)
    assert baseline[0] == "data-end", (
        f"with ses:SendRawEmail granted, SES must accept MAIL FROM and RCPT TO and defer to "
        f"end-of-DATA; the authorized baseline was instead refused at phase {baseline[0]!r}: "
        f"{baseline[1]} {baseline[2]!r}"
    )
    assert baseline[1] == 554, (
        f"the authorized baseline must be the identity gate's 554; got {baseline[1]} {baseline[2]!r}"
    )
    assert baseline[2].startswith("Message rejected: Email address is not verified."), (
        f"the authorized baseline must be the identity refusal, so the revoked arm is compared "
        f"against the right thing; got {baseline[2]!r}"
    )

    # --- Beat 2, break exactly one thing: remove the send permission. Nothing else changes — same
    #     user, same access key, same derived password, same sender, same recipient, same body.
    iam.delete_user_policy(UserName=user, PolicyName=policy)
    denied = _poll_until_verdict(
        lambda verdict: verdict != baseline,
        _REVOKE_PROPAGATION_DEADLINE_S,
        host,
        port,
        access_key_id,
        password,
        sender,
        "revoking ses:SendRawEmail never changed the SMTP submission verdict, so the SMTP front "
        "door is not evaluating the IAM policy at all",
    )

    # --- Beat 3, assert the specific fault: a permanent refusal, attributable to authorization.
    assert denied[1] >= 500, (
        f"the unauthorized submission must be refused with a permanent failure; got {denied!r} "
        f"against the authorized baseline {baseline!r}"
    )
    denied_text = denied[2].lower()
    assert any(marker in denied_text for marker in _AUTHORIZATION_MARKERS), (
        f"the unauthorized refusal must be attributable to AUTHORIZATION rather than read as a "
        f"generic failure — repost.aws/knowledge-center/amazon-ses-iam-user-email-access-denied "
        f"documents '554 Access denied' for exactly this policy gap; expected one of "
        f"{_AUTHORIZATION_MARKERS!r} in the reply, got {denied!r}"
    )

    # --- Beat 4, effect absent, on an independent read at the control plane: the grant really is
    #     gone, via a different operation than the one that removed it.
    try:
        still = iam.get_user_policy(UserName=user, PolicyName=policy)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        assert code == "NoSuchEntity", (
            f"GetUserPolicy for the revoked policy raised {code!r}, expected 'NoSuchEntity'"
        )
        msg = exc.response.get("Error", {}).get("Message")
        expected_msg = f"The user policy with name {policy} cannot be found."
        assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"
    else:
        raise AssertionError(
            f"GetUserPolicy still returns a document for {policy!r} after DeleteUserPolicy: "
            f"{still.get('PolicyDocument')!r} — the control under test was never actually removed"
        )
    stats_mid = ses.get_send_statistics()["SendDataPoints"]
    assert stats_mid == stats_before, (
        f"GetSendStatistics moved from {stats_before!r} to {stats_mid!r} across two refused "
        f"submissions; neither a 554 nor an authorization refusal is a delivery attempt"
    )

    # --- Beat 5, restore: put the identical policy back. This is the two-sided leg — a target that
    #     fakes the control by permanently souring the credential fails here.
    iam.put_user_policy(
        UserName=user, PolicyName=policy, PolicyDocument=json.dumps(_SEND_POLICY)
    )
    restored = _poll_until_verdict(
        lambda verdict: verdict == baseline,
        _RESTORE_PROPAGATION_DEADLINE_S,
        host,
        port,
        access_key_id,
        password,
        sender,
        f"re-granting ses:SendRawEmail never restored the original verdict {baseline!r}; the SMTP "
        f"front door's authorization decision is one-way",
    )

    # --- Beat 6, the identical call now behaves identically, and STABLY. The poll above already
    #     demanded equality with the baseline, so re-asserting it here would be an assertion that
    #     cannot fail; what is genuinely new is one FURTHER submission after the poll returned, which
    #     proves the restored state is the steady state rather than one lucky frontend.
    confirmed = _submit(host, port, access_key_id, password, sender, converge_auth=False)
    assert confirmed == restored == baseline, (
        f"the restored verdict must be stable, not a single frontend agreeing once: the poll settled "
        f"on {restored!r} and the next identical submission answered {confirmed!r}, against the "
        f"authorized baseline {baseline!r}"
    )
    # botocore decodes IAM's URL-encoded PolicyDocument into a dict. The grant is asserted by
    # CONTENT rather than by whole-document equality, because IAM is free to normalise a
    # single-element Action list to a bare string and that normalisation is not the subject here.
    restored_document = iam.get_user_policy(UserName=user, PolicyName=policy)["PolicyDocument"]
    statements = restored_document["Statement"]
    granted = {
        action
        for statement in statements
        if statement["Effect"] == "Allow"
        for action in (
            [statement["Action"]] if isinstance(statement["Action"], str) else statement["Action"]
        )
    }
    assert "ses:SendRawEmail" in granted, (
        f"the restored inline policy must grant ses:SendRawEmail again; GetUserPolicy reported "
        f"allowed actions {sorted(granted)!r} in {restored_document!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
