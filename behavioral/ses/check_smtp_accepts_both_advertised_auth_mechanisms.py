"""smtp-accepts-both-advertised-auth-mechanisms."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import smtplib
import time

from behavioral_harness import tags

CHECK = "smtp-accepts-both-advertised-auth-mechanisms"
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


def _advertised_mechanisms(ctx) -> list[str]:
    """The AUTH mechanisms the listener advertises, read over a short-lived connection."""
    session = smtplib.SMTP(*ctx.service_host(_smtp_host(ctx.region), _SMTP_PORT), timeout=30)
    try:
        code, banner = session.ehlo()
        assert code == 250, f"EHLO answered {code!r}: {banner!r}"
        return session.esmtp_features.get("auth", "").split()
    finally:
        _quietly_close(session)


def _authenticate(ctx, mechanism: str, username: str, password: str):
    """Upgrade a session and AUTH with exactly `mechanism`, retrying IAM propagation.

    smtplib's login() picks a mechanism itself, which is precisely what must not happen here:
    the claim is about each ADVERTISED mechanism individually, so the authobject is chosen by
    name. A newly minted access key is not yet effective at the listener and SES reports that
    with the same 535 it uses for a wrong password, hence the bounded retry.
    """
    host, port = ctx.service_host(_smtp_host(ctx.region), _SMTP_PORT)
    last: Exception | None = None
    deadline = time.monotonic() + _PROPAGATION_TIMEOUT_S
    while time.monotonic() < deadline:
        session = smtplib.SMTP(host, port, timeout=30)
        session.ehlo()
        session.starttls()
        session.ehlo()
        session.user = username
        session.password = password
        authobject = session.auth_plain if mechanism == "PLAIN" else session.auth_login
        try:
            code, response = session.auth(mechanism, authobject)
            return session, code, response
        except smtplib.SMTPAuthenticationError as exc:
            last = exc
            _quietly_close(session)
            time.sleep(_PROPAGATION_DELAY_S)
    raise AssertionError(
        f"AUTH {mechanism} at {host}:{port} never accepted a freshly minted credential "
        f"within {_PROPAGATION_TIMEOUT_S:.0f}s; last was {last!r}"
    )


@tags(
    "axis:happy-path",
    "cap:c6",
    "cap:c7",
    "concern:data-plane",
    "concern:representation",
    "dp:native",
    "plane:data",
)
def run(ctx) -> None:
    """The SES SMTP listener advertises exactly AUTH PLAIN and LOGIN, both authenticate the same
    SigV4-derived credential with 235 "Authentication successful." and a session that then accepts an
    envelope, and the advertisement is the same on a later connection."""
    username, password = _smtp_credential(ctx)

    # Read the banner on its own short-lived connection and close it. SES drops an idle session
    # inside ~13 s with `451 4.4.2 Timeout waiting for data from client.`, so a probe socket held
    # open across the propagation retries below would report an empty capability set later.
    advertised = _advertised_mechanisms(ctx)
    assert advertised == ["PLAIN", "LOGIN"], (
        f"listener advertises AUTH mechanisms {advertised!r}, expected ['PLAIN', 'LOGIN']"
    )

    for mechanism in advertised:
        session, code, response = _authenticate(ctx, mechanism, username, password)
        ctx.on_cleanup(lambda s=session: _quietly_close(s))
        assert code == 235, (
            f"AUTH {mechanism} answered {code!r}: {response!r}, expected 235"
        )
        assert response == b"Authentication successful.", (
            f"AUTH {mechanism} answered 235 {response!r}, expected b'Authentication successful.'"
        )

        # The 235 has to mean something: the session must now be authorised to submit, rather
        # than still answering the unauthenticated 530.
        code, response = session.docmd("MAIL", f"FROM:<sender@{ctx.unique_name('d-')}.example.com>")
        assert code == 250, (
            f"MAIL FROM after AUTH {mechanism} answered {code!r}: {response!r}, expected 250 — a "
            f"235 that does not authorise the envelope is not an authentication"
        )
        code, response = session.rset()
        assert code == 250, f"RSET after AUTH {mechanism} answered {code!r}: {response!r}"

    # The advertisement is stable state, not a per-connection choice.
    again = _advertised_mechanisms(ctx)
    assert again == advertised, (
        f"a fresh connection advertised {again!r} but the first said {advertised!r}; the mechanism "
        f"list must not vary from one session to the next"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
