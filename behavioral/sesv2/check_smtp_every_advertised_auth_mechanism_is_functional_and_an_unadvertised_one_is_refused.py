"""smtp-every-advertised-auth-mechanism-is-functional-and-an-unadvertised-one-is-refused."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import smtplib
import socket
import ssl
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "smtp-every-advertised-auth-mechanism-is-functional-and-an-unadvertised-one-is-refused"
GROUP = "rejected"
SERVICES = ["sesv2"]

# ===== helpers =====
# The EHLO response is read through a raw TLS socket, not smtplib.esmtp_features, because
# esmtp_features lower-cases every keyword and this check needs the mechanism names as SES sent them.

_SMTP_PORT = 465  # implicit TLS ("TLS Wrapper", smtp-connect.html); the only port the runner reaches
_CONNECT_TIMEOUT_S = 30.0
#: Bounded convergence for a freshly minted IAM access key on the SMTP frontends. Raises, never sleeps.
_AUTH_CONVERGENCE_DEADLINE_S = 150.0
_AUTH_RETRY_INTERVAL_S = 5.0

# https://docs.aws.amazon.com/ses/latest/dg/smtp-credentials.html
_DERIVE_DATE = "11111111"
_DERIVE_SERVICE = "ses"
_DERIVE_TERMINAL = "SendRawEmail"
_DERIVE_VERSION = 0x04

#: RFC-registered SASL mechanisms an SMTP server may offer. The check does not assume which of these
#: SES advertises — it partitions this table by the target's OWN EHLO response, so the expectation
#: for every row is derived rather than pinned (B3, "the target's own reported state").
_KNOWN_MECHANISMS = ("PLAIN", "LOGIN", "CRAM-MD5", "DIGEST-MD5", "EXTERNAL", "XOAUTH2")
#: The subset this check knows how to drive to a verdict. A mechanism SES advertises that is NOT
#: here is a finding (SES gained a mechanism), not something to skip.
_DRIVEABLE = ("PLAIN", "LOGIN")

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
    """A TLS socket opened by hand so the raw EHLO bytes are readable. A connect or handshake
    failure carries the data-plane sentinel: nothing listening is a fidelity finding about the
    target, not an environment error to be excluded from the published rate."""
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
            raise AssertionError(
                f"the SMTP listener closed the connection mid-reply after {buf!r}"
            )
        buf += chunk
        lines = buf.split(b"\r\n")
        # A reply is complete when its last full line uses a SPACE at index 3 (RFC 5321 s4.2.1).
        if len(lines) >= 2 and lines[-1] == b"" and len(lines[-2]) >= 4 and lines[-2][3:4] == b" ":
            return [line.decode("ascii", "replace") for line in lines[:-1]]
    raise AssertionError(
        f"the SMTP listener sent no complete reply within {_CONNECT_TIMEOUT_S}s; buffer was {buf!r}"
    )


def _ehlo_capabilities(host: str, port: int) -> dict[str, str]:
    """{KEYWORD: parameter-text} from the EHLO response, in the case SES sent it."""
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
    for line in reply[1:]:  # line 0 is the greeting domain, never a capability
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


def _session(host: str, port: int) -> smtplib.SMTP_SSL:
    smtp = smtplib.SMTP_SSL(
        host, port, timeout=_CONNECT_TIMEOUT_S, context=ssl._create_unverified_context()
    )
    smtp.ehlo()
    return smtp


def _auth_object(mechanism: str, user: str, password: str):
    """A SASL responder for one mechanism, written out rather than borrowed from smtplib's bound
    `auth_plain`/`auth_login`, which read `self.user`/`self.password` set by `login()` — the very
    call this check is avoiding, because login() picks ONE mechanism and hides which."""
    if mechanism == "PLAIN":
        return lambda challenge=None: f"\0{user}\0{password}"
    if mechanism == "LOGIN":
        return lambda challenge=None: (user if challenge is None else password)
    raise AssertionError(
        f"no responder is implemented for advertised mechanism {mechanism!r}; SES advertising a "
        f"mechanism this check cannot drive is a finding, not a leg to skip"
    )


def _try_auth(host: str, port: int, mechanism: str, user: str, password: str):
    """(smtp, code, message) on acceptance; (None, code, message) on refusal. No retry: the caller
    decides whether a refusal is the answer or a propagation artifact."""
    smtp = _session(host, port)
    try:
        code, message = smtp.auth(mechanism, _auth_object(mechanism, user, password))
    except smtplib.SMTPAuthenticationError as exc:
        smtp.close()
        return None, exc.smtp_code, exc.smtp_error
    return smtp, code, message


def _authed(host: str, port: int, mechanism: str, user: str, password: str):
    """(smtp, code, message) for an authenticated session over ONE named mechanism, with a bounded
    convergence retry that RAISES on the deadline. A freshly minted IAM access key is not immediately
    usable on every SES SMTP frontend and no API reports when it becomes usable.

    The OBSERVED reply is returned rather than asserted away here: the caller compares the replies
    the mechanisms actually gave, and an assertion in this helper against a constant would make that
    comparison a tautology over a value this function had already forced.
    """
    deadline = time.monotonic() + _AUTH_CONVERGENCE_DEADLINE_S
    last: object = None
    attempts = 0
    while time.monotonic() < deadline:
        attempts += 1
        smtp, code, message = _try_auth(host, port, mechanism, user, password)
        if smtp is not None:
            assert code == 235, (
                f"AUTH {mechanism} returned a session on a non-235 reply {(code, message)!r}; "
                f"RFC 4954 s4 gives 235 for a successful authentication"
            )
            return smtp, code, message
        last = (code, message)
        time.sleep(_AUTH_RETRY_INTERVAL_S)
    raise AssertionError(
        f"AUTH {mechanism} with the correctly derived password never succeeded within "
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
    """Every AUTH mechanism SES advertises accepts the derived SMTP password with the same 235 reply
    and refuses a wrong secret with the same 535 reply; a failed AUTH leaves the session
    unauthenticated, a second AUTH is refused 503, and an unadvertised mechanism draws no challenge."""
    iam = ctx.client("iam")
    sesv2 = ctx.client("sesv2")
    host, port = ctx.service_host(f"email-smtp.{ctx.region}.amazonaws.com", _SMTP_PORT)

    # A confound to rule out before any 535 is interpreted: an account-level sending pause would
    # also change what the front door says. Read it once, from the v2 account API.
    assert sesv2.get_account()["SendingEnabled"] is True, (
        "setup precondition: account-level sending must be ENABLED, or an AUTH-phase refusal cannot "
        "be attributed to the credential; GetAccount reported SendingEnabled false"
    )

    caps = _ehlo_capabilities(host, port)
    assert "AUTH" in caps, (
        f"EHLO advertised {sorted(caps)!r} with no AUTH keyword; SES must offer authentication on "
        f"the TLS listener"
    )
    advertised = [m.upper() for m in caps["AUTH"].split()]
    assert advertised, (
        f"the AUTH keyword advertised no mechanisms at all: {caps['AUTH']!r}"
    )
    undriveable = sorted(set(advertised) - set(_DRIVEABLE))
    assert not undriveable, (
        f"SES advertises mechanism(s) {undriveable!r} that this check has no responder for; that is "
        f"a change in the SES SMTP contract to record, not a leg to skip. Advertised: {advertised!r}"
    )
    unadvertised = [m for m in _KNOWN_MECHANISMS if m not in advertised]
    assert unadvertised, (
        f"the negative arm needs at least one registered mechanism SES does NOT advertise; SES "
        f"advertised all of {_KNOWN_MECHANISMS!r}"
    )

    # AWS documents that SMTP credentials cannot be derived from temporary credentials, so the check
    # mints a long-lived key of its own rather than reusing the harness session.
    user = ctx.unique_name("sim2real-behav-smtp-auth-")
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

    # A wrong secret of the identical SHAPE: same derivation, same version byte, same 33 bytes, only
    # the IAM secret differs. So a target that validates the ENVELOPE of the credential rather than
    # the credential itself cannot tell them apart, and 535 has to come from the keyed hash.
    wrong_password = _smtp_password(base64.b64encode(secrets.token_bytes(30)).decode(), ctx.region)
    assert wrong_password != password, "the wrong-secret probe must differ from the real password"
    assert len(base64.b64decode(wrong_password)) == len(base64.b64decode(password)) == 33, (
        "both passwords must decode to 33 bytes (one version byte + a SHA-256 HMAC), so only the "
        "secret distinguishes them"
    )

    accept_replies: dict[str, tuple[int, bytes]] = {}
    refuse_replies: dict[str, tuple[int, bytes]] = {}

    for mechanism in advertised:
        # --- Beat 1, positive control: this mechanism authenticates, and the session it produced is
        #     really authorized — proved through a DIFFERENT verb than AUTH.
        smtp, accept_code, accept_message = _authed(host, port, mechanism, access_key_id, password)
        try:
            accept_replies[mechanism] = (accept_code, accept_message)
            code, message = smtp.docmd("MAIL", f"FROM:<probe@{ctx.region}.example.com>")
            assert code == 250, (
                f"after AUTH {mechanism} succeeded, MAIL FROM must be accepted — otherwise the 235 "
                f"authenticated nothing; got {code} {message!r}"
            )

            # --- Beat 2: a second AUTH on this authenticated session must be refused 503.
            #     smtplib.auth() RETURNS 503 instead of raising, so read the code, do not rely on
            #     an exception.
            try:
                reauth_code, reauth_message = smtp.auth(
                    mechanism, _auth_object(mechanism, access_key_id, password)
                )
            except smtplib.SMTPAuthenticationError as exc:
                reauth_code, reauth_message = exc.smtp_code, exc.smtp_error
            assert reauth_code == 503, (
                f"a second AUTH {mechanism} on an already-authenticated session must be refused 503 "
                f"(RFC 4954 s4); got {reauth_code} {reauth_message!r}"
            )
        finally:
            try:
                smtp.quit()
            except smtplib.SMTPException:
                smtp.close()

        # --- Beat 3, break exactly one thing: the same mechanism, the same access key id, a secret
        #     that is wrong. No retry here — for this arm a 535 IS the answer.
        refused, refuse_code, refuse_message = _try_auth(
            host, port, mechanism, access_key_id, wrong_password
        )
        assert refused is None, (
            f"AUTH {mechanism} with a password derived from a DIFFERENT secret was ACCEPTED; the "
            f"endpoint is not verifying the keyed hash at all"
        )
        assert refuse_code == 535, (
            f"AUTH {mechanism} with a wrong secret must be refused 535; got {refuse_code} "
            f"{refuse_message!r}"
        )
        refuse_replies[mechanism] = (refuse_code, refuse_message)

        # --- Beat 4, effect absent: the failed AUTH left the session unauthenticated, proved at the
        #     protocol level rather than by inspecting our own state.
        probe = _session(host, port)
        try:
            code, message = probe.auth(mechanism, _auth_object(mechanism, access_key_id, "not-it"))
        except smtplib.SMTPAuthenticationError:
            pass_code, pass_message = probe.docmd("MAIL", f"FROM:<probe@{ctx.region}.example.com>")
            assert pass_code == 530, (
                f"after a failed AUTH {mechanism}, MAIL FROM must be refused 530; got {pass_code} "
                f"{pass_message!r}"
            )
            assert pass_message == b"Authentication required", (
                f"the post-failure MAIL FROM refusal was {pass_message!r}, expected "
                f"b'Authentication required'"
            )
        else:
            raise AssertionError(
                f"AUTH {mechanism} with the literal secret 'not-it' answered {(code, message)!r} "
                f"instead of raising; any password must not authenticate"
            )
        finally:
            probe.close()

        # --- Beat 5, restore: the identical mechanism with the correct password succeeds again, so
        #     the 535 was about the secret and not about the mechanism or the frontend.
        restored, restored_code, restored_message = _authed(
            host, port, mechanism, access_key_id, password
        )
        restored.close()
        assert (restored_code, restored_message) == accept_replies[mechanism], (
            f"after the 535, AUTH {mechanism} with the correct password must answer exactly as it did "
            f"before it; expected {accept_replies[mechanism]!r}, got "
            f"{(restored_code, restored_message)!r}"
        )

    # --- Beat 6, the mechanisms must AGREE, and on SES's exact reply. One
    #     assertion carries both: a single-element set is the agreement, and its member is the
    #     corroborated literal. Every value in the dict is what the target actually said.
    assert set(accept_replies.values()) == {(235, b"Authentication successful.")}, (
        f"every advertised mechanism must accept the correct credential with the IDENTICAL reply, and "
        f"that reply is the measured (235, b'Authentication successful.'); got {accept_replies!r}"
    )
    assert set(refuse_replies.values()) == {(535, b"Authentication Credentials Invalid")}, (
        f"every advertised mechanism must refuse a wrong secret with the IDENTICAL reply, and that "
        f"reply is the measured (535, b'Authentication Credentials Invalid'); got {refuse_replies!r}"
    )

    # --- Beat 7, the advertisement is CLOSED: a registered mechanism SES did not advertise is
    #     refused permanently, and never gets as far as a challenge.
    unadvertised_replies = {}
    for mechanism in unadvertised:
        probe = _session(host, port)
        try:
            code, message = probe.docmd("AUTH", mechanism)
        finally:
            probe.close()
        assert code >= 500, (
            f"AUTH {mechanism} is not in SES's advertised mechanism list {advertised!r} and must be "
            f"refused with a permanent failure; got {code} {message!r}"
        )
        assert code not in (235, 334), (
            f"AUTH {mechanism} answered {code} {message!r} — an unadvertised mechanism must neither "
            f"succeed (235) nor issue a challenge (334)"
        )
        unadvertised_replies[mechanism] = code
    assert len(set(unadvertised_replies.values())) == 1, (
        f"every unadvertised mechanism must be refused with the SAME code — one fault class, one "
        f"code; got {unadvertised_replies!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
