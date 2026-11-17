"""smtp-rejects-a-tampered-sigv4-derived-password."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import smtplib
import time

from behavioral_harness import tags

CHECK = "smtp-rejects-a-tampered-sigv4-derived-password"
GROUP = "smtp-data-plane"
SERVICES = ["ses"]

_SMTP_PORT = 587
_SMTP_PASSWORD_VERSION = 0x04
_SIGV4_DATE = "11111111"
_SIGV4_SERVICE = "ses"
_SIGV4_TERMINAL = "aws4_request"
_SIGV4_MESSAGE = "SendRawEmail"

_PROPAGATION_TIMEOUT_S = 90.0
_PROPAGATION_DELAY_S = 2.0


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


def _smtp_credential(ctx) -> tuple[str, str, str]:
    """Mint an IAM user and return (access key id, correct SMTP password, secret key).

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
    secret = key["SecretAccessKey"]
    return key["AccessKeyId"], _smtp_password(secret, ctx.region), secret


def _quietly_close(session: smtplib.SMTP) -> None:
    try:
        session.quit()
    except (smtplib.SMTPException, OSError):
        try:
            session.close()
        except OSError:
            pass


def _upgraded_session(ctx) -> smtplib.SMTP:
    session = smtplib.SMTP(*ctx.service_host(_smtp_host(ctx.region), _SMTP_PORT), timeout=30)
    session.ehlo()
    session.starttls()
    session.ehlo()
    return session


def _authenticated_session(ctx, username: str, password: str) -> smtplib.SMTP:
    """STARTTLS then AUTH, retrying the IAM propagation window at first use of the credential.

    A newly minted access key is not yet effective at the SMTP listener, and SES reports that
    with the SAME 535 it uses for a genuinely wrong password. Establishing the positive control
    through this retry FIRST is therefore load-bearing for this whole check: without it, the
    535 asserted below would be indistinguishable from having simply tried too early.
    """
    host, port = ctx.service_host(_smtp_host(ctx.region), _SMTP_PORT)
    last: Exception | None = None
    deadline = time.monotonic() + _PROPAGATION_TIMEOUT_S
    while time.monotonic() < deadline:
        session = _upgraded_session(ctx)
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


@tags(
    "axis:rejection",
    "cap:c6",
    "cap:c7",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:native",
    "plane:data",
)
def run(ctx) -> None:
    """An SMTP password derived from a permuted secret, same length and version byte, is refused with
    535 "Authentication Credentials Invalid" and that session's envelope with 530 "Authentication
    required", while the correctly derived password for the same access key authenticates."""
    username, good_password, secret = _smtp_credential(ctx)

    # Positive control FIRST, and through the propagation retry: this access key id, with the
    # correctly derived password, is accepted. Only after this does a 535 mean "wrong password".
    good = _authenticated_session(ctx, username, good_password)
    ctx.on_cleanup(lambda: _quietly_close(good))
    code, response = good.noop()
    assert code == 250, f"authenticated session NOOP answered {code!r}: {response!r}"

    # Break exactly one thing: derive the password from a permuted secret, same algorithm, same
    # region, same access key id, same session setup.
    bad_password = _smtp_password(secret[::-1], ctx.region)
    assert bad_password != good_password, (
        "the tampered secret produced the same SMTP password as the real one, so the negative "
        "below would be vacuous"
    )
    assert len(bad_password) == len(good_password), (
        f"tampered password is {len(bad_password)} chars vs {len(good_password)} for the good "
        f"one; SES must reject it on content, not on a length or format difference"
    )
    assert base64.b64decode(bad_password)[0] == _SMTP_PASSWORD_VERSION, (
        f"tampered password does not carry the SES version byte "
        f"{_SMTP_PASSWORD_VERSION:#x}, so it is malformed rather than merely wrong"
    )

    bad = _upgraded_session(ctx)
    ctx.on_cleanup(lambda: _quietly_close(bad))
    try:
        bad.login(username, bad_password)
    except smtplib.SMTPAuthenticationError as exc:
        auth_code, auth_message = exc.smtp_code, exc.smtp_error
    else:
        raise AssertionError(
            f"AUTH SUCCEEDED for access key {username!r} with a password derived from a permuted "
            f"secret — the listener is not verifying the derivation at all"
        )

    assert auth_code == 535, f"tampered-password AUTH answered {auth_code!r}, expected 535"
    assert auth_message == b"Authentication Credentials Invalid", (
        f"tampered-password AUTH answered 535 {auth_message!r}, expected "
        f"b'Authentication Credentials Invalid'"
    )

    # Effect absent: the rejected AUTH granted nothing, so the envelope is refused on that
    # session with the unauthenticated 530 rather than accepted.
    code, response = bad.docmd("MAIL", "FROM:<nobody@example.com>")
    assert code == 530, (
        f"MAIL FROM after the rejected AUTH answered {code!r}: {response!r}, expected 530 — a "
        f"failed AUTH must leave the session unauthorised to submit"
    )
    assert response == b"Authentication required", (
        f"MAIL FROM answered 530 {response!r}, expected b'Authentication required'"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
