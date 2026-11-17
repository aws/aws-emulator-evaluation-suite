"""smtp-auth-before-starttls-is-rejected."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import smtplib
import time

from behavioral_harness import tags

CHECK = "smtp-auth-before-starttls-is-rejected"
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
    with the SAME 535 it uses for a genuinely wrong password — so this bounded retry is what
    makes any later 535 assertion mean 'wrong credential' rather than 'too early'.
    """
    host, port = ctx.service_host(_smtp_host(ctx.region), _SMTP_PORT)
    last: Exception | None = None
    deadline = time.monotonic() + _PROPAGATION_TIMEOUT_S
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


@tags(
    "axis:rejection",
    "cap:c6",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:native",
    "plane:data",
)
def run(ctx) -> None:
    """AUTH on a plaintext SES submission session is refused with 530 "Must issue a STARTTLS command
    first" and the envelope then with 530 "Authentication required", while the same credential
    authenticates once STARTTLS has run."""
    username, password = _smtp_credential(ctx)
    host, port = ctx.service_host(_smtp_host(ctx.region), _SMTP_PORT)

    # Positive control FIRST: this exact credential is good, and the listener accepts it on an
    # upgraded session. Without this the 530 below could just mean "bad password".
    good = _authenticated_session(ctx, username, password)
    ctx.on_cleanup(lambda: _quietly_close(good))
    code, response = good.noop()
    assert code == 250, f"authenticated session NOOP answered {code!r}: {response!r}"

    # Break exactly one thing: skip STARTTLS, change nothing else.
    plain = smtplib.SMTP(host, port, timeout=30)
    ctx.on_cleanup(lambda: _quietly_close(plain))
    code, banner = plain.ehlo()
    assert code == 250, f"plaintext EHLO answered {code!r}: {banner!r}"
    assert "starttls" in plain.esmtp_features, (
        f"listener did not advertise STARTTLS at all ({sorted(plain.esmtp_features)!r}); the "
        "refusal below would then be untestable"
    )

    try:
        plain.login(username, password)
    except smtplib.SMTPAuthenticationError as exc:
        auth_code, auth_message = exc.smtp_code, exc.smtp_error
    else:
        raise AssertionError(
            "AUTH succeeded on a PLAINTEXT submission session — SES must refuse a credential "
            "before the connection is encrypted"
        )

    assert auth_code == 530, f"plaintext AUTH answered {auth_code!r}, expected 530"
    assert auth_message == b"Must issue a STARTTLS command first", (
        f"plaintext AUTH answered 530 {auth_message!r}, expected "
        f"b'Must issue a STARTTLS command first'"
    )

    # Effect absent: the refusal left the session unauthenticated, so the envelope is refused
    # too — and with the OTHER 530 message, not this one.
    code, response = plain.docmd("MAIL", "FROM:<nobody@example.com>")
    assert code == 530, (
        f"MAIL FROM on the unauthenticated plaintext session answered {code!r}: {response!r}, "
        f"expected 530 — the failed AUTH must not have left the session authorised to submit"
    )
    assert response == b"Authentication required", (
        f"MAIL FROM answered 530 {response!r}, expected b'Authentication required'"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
