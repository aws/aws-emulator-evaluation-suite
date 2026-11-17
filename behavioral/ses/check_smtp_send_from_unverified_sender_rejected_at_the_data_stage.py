"""smtp-send-from-unverified-sender-rejected-at-the-data-stage."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import smtplib
import time

from behavioral_harness import tags

CHECK = "smtp-send-from-unverified-sender-rejected-at-the-data-stage"
GROUP = "smtp-data-plane"
SERVICES = ["ses"]

# ===== helpers =====

_SMTP_PORT = 587
_SMTP_PASSWORD_VERSION = 0x04
_SIGV4_DATE = "11111111"
_SIGV4_SERVICE = "ses"
_SIGV4_TERMINAL = "aws4_request"
_SIGV4_MESSAGE = "SendRawEmail"

_PROPAGATION_TIMEOUT_S = 90.0
_PROPAGATION_DELAY_S = 2.0

# AWS's universal mailbox simulator. Deliverable from every account, including a sandbox one,
# so the RECIPIENT cannot be the reason this send fails — the sender is the only broken thing.
_SIMULATOR_RECIPIENT = "success@simulator.amazonses.com"


def _smtp_host(region: str) -> str:
    """SES's native submission endpoint for a region. Never a literal: ctx.region decides."""
    return f"email-smtp.{region}.amazonaws.com"


def _smtp_password(secret_access_key: str, region: str) -> str:
    """AWS's documented derivation of an SES SMTP password from an IAM secret access key."""
    def _sign(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    signature = _sign(("AWS4" + secret_access_key).encode("utf-8"), _SIGV4_DATE)
    for part in (region, _SIGV4_SERVICE, _SIGV4_TERMINAL, _SIGV4_MESSAGE):
        signature = _sign(signature, part)
    return base64.b64encode(bytes([_SMTP_PASSWORD_VERSION]) + signature).decode("ascii")


def _smtp_credential(ctx) -> tuple[str, str]:
    """Mint an IAM user whose access key is a usable SES SMTP credential.

    Cleanup is registered immediately after create_user and enumerates keys and inline
    policies at teardown time, so it undoes whatever this function went on to attach.
    """
    iam = ctx.client("iam")
    user = ctx.unique_name("sim2real-behav-ses-smtp-")
    iam.create_user(UserName=user, Tags=[{"Key": "sim2real", "Value": CHECK}])

    def _reap_user() -> None:
        for meta in iam.list_access_keys(UserName=user)["AccessKeyMetadata"]:
            iam.delete_access_key(UserName=user, AccessKeyId=meta["AccessKeyId"])
        for name in iam.list_user_policies(UserName=user)["PolicyNames"]:
            iam.delete_user_policy(UserName=user, PolicyName=name)
        iam.delete_user(UserName=user)

    ctx.on_cleanup(_reap_user)

    iam.put_user_policy(
        UserName=user,
        PolicyName="ses-smtp-send",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "ses:SendRawEmail", "Resource": "*"}],
        }),
    )
    key = iam.create_access_key(UserName=user)["AccessKey"]
    return key["AccessKeyId"], _smtp_password(key["SecretAccessKey"], ctx.region)


def _quietly_close(session: smtplib.SMTP) -> None:
    try:
        session.quit()
    except (smtplib.SMTPException, OSError):
        try:
            session.close()
        except OSError:
            pass


def _authenticated_session(ctx, username: str, password: str) -> smtplib.SMTP:
    """STARTTLS then AUTH, retrying the IAM propagation window at first use of the credential.

    A newly minted access key is not yet effective at the SMTP listener, and SES reports that
    with the SAME 535 it uses for a wrong password — so this bounded retry is what stops an
    IAM-propagation race from being read as a rejection of the send.
    """
    host, port = ctx.service_host(_smtp_host(ctx.region), _SMTP_PORT)
    last: Exception | None = None
    left = ctx.time_left()
    deadline = time.monotonic() + (_PROPAGATION_TIMEOUT_S if left is None else min(_PROPAGATION_TIMEOUT_S, left))
    while time.monotonic() < deadline:
        session = smtplib.SMTP(host, port, timeout=30)
        session.ehlo()
        session.starttls()
        session.ehlo()
        try:
            session.login(username, password)
            return session
        except smtplib.SMTPAuthenticationError as exc:
            last = exc
            _quietly_close(session)
            time.sleep(_PROPAGATION_DELAY_S)
    raise AssertionError(
        f"the SMTP listener at {host}:{port} never accepted a freshly minted credential "
        f"within {_PROPAGATION_TIMEOUT_S:.0f}s; last response was {last!r}"
    )


def _all_identities(ses) -> set[str]:
    """Every SES identity in the account, paginated: other identities can push ours off page one."""
    found: set[str] = set()
    for page in ses.get_paginator("list_identities").paginate():
        found.update(page["Identities"])
    return found


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
    """Over SES's SMTP listener an unverified sender is accepted through MAIL FROM and RCPT TO, then
    refused at DATA with 554 'Message rejected: Email address is not verified.' naming the sender
    and region (SMTPDataError, not SMTPSenderRefused), and the session survives the refusal."""
    ses = ctx.client("ses")
    username, password = _smtp_credential(ctx)

    # The sender is a name only this check occupies, so "unverified" is a property of OUR
    # query rather than a snapshot of the account. Establish it rather than assume it.
    sender = ctx.unique_name("sim2real-behav-ses-") + "@example.com"
    attrs = ses.get_identity_verification_attributes(Identities=[sender])
    assert attrs["VerificationAttributes"] == {}, (
        f"{sender!r} already has verification attributes {attrs['VerificationAttributes']!r}; "
        f"the precondition of this check is that it is unknown to SES"
    )
    before = _all_identities(ses)
    assert sender not in before, f"{sender!r} is already an identity in this account"

    session = _authenticated_session(ctx, username, password)
    ctx.on_cleanup(lambda: _quietly_close(session))

    message = (
        f"From: {sender}\r\n"
        f"To: {_SIMULATOR_RECIPIENT}\r\n"
        f"Subject: {CHECK}\r\n"
        f"\r\n"
        f"test message from an unverified sender; must never be accepted\r\n"
    )
    try:
        session.sendmail(sender, [_SIMULATOR_RECIPIENT], message)
    except smtplib.SMTPDataError as exc:
        data_code, data_message = exc.smtp_code, exc.smtp_error.decode("utf-8", "replace")
    except smtplib.SMTPSenderRefused as exc:
        raise AssertionError(
            f"SES refused the sender at the MAIL FROM stage ({exc.smtp_code} "
            f"{exc.smtp_error!r}); real AWS accepts the envelope and refuses at DATA"
        ) from exc
    else:
        raise AssertionError(
            f"the SMTP listener ACCEPTED a message from the unverified sender {sender!r} — an "
            f"unverified From must be refused on every plane, sandbox or production"
        )

    assert data_code == 554, f"DATA stage answered {data_code!r}, expected 554"
    expected = (
        "Message rejected: Email address is not verified. The following identities failed the "
        f"check in region {ctx.region.upper()}: {sender}"
    )
    assert data_message == expected, (
        f"DATA stage answered 554 {data_message!r}, expected {expected!r}"
    )

    # Effect absent: SES did not mint an identity for the sender it just refused.
    after = _all_identities(ses)
    assert sender not in after, (
        f"{sender!r} appeared in ListIdentities after the refused send — a rejected submission "
        f"must not create the identity it rejected"
    )

    # Positive control, in the same plane and on the same session: the envelope stage really
    # does accept both addresses, and the session is alive after the 554. So the refusal was
    # of the MESSAGE at DATA, not of the connection, the credential or the recipient.
    code, response = session.docmd("MAIL", f"FROM:<{sender}>")
    assert code == 250, (
        f"MAIL FROM <{sender}> answered {code!r}: {response!r}, expected 250 — sender "
        f"verification must not be enforced at the envelope stage"
    )
    code, response = session.docmd("RCPT", f"TO:<{_SIMULATOR_RECIPIENT}>")
    assert code == 250, (
        f"RCPT TO <{_SIMULATOR_RECIPIENT}> answered {code!r}: {response!r}, expected 250"
    )
    code, response = session.rset()
    assert code == 250, (
        f"RSET after the 554 answered {code!r}: {response!r}, expected 250 — SES must reject the "
        f"message without tearing down the authenticated session"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
