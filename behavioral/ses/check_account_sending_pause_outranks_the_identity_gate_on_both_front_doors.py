"""account-sending-pause-outranks-the-identity-gate-on-both-front-doors."""
# UpdateAccountSendingEnabled is one flag per account per region; the re-enable is registered with
# ctx.on_cleanup before the flag is cleared, so a mid-check failure cannot leave the account paused.
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import smtplib
import ssl
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "account-sending-pause-outranks-the-identity-gate-on-both-front-doors"
GROUP = "server-side"
SERVICES = ["ses"]

# ===== helpers =====
# The SMTP password derivation is the documented formula (smtp-credentials.html); port 465 is
# SES's implicit-TLS SMTP port.
_SMTP_PORT = 465
_DERIVE_DATE = "11111111"
_DERIVE_SERVICE = "ses"
_DERIVE_TERMINAL = "SendRawEmail"
_DERIVE_VERSION = 0x04
_RECIPIENT = "success@simulator.amazonses.com"
_BASELINE_PREFIX = "Message rejected: Email address is not verified."


def _client_error(fn) -> dict:
    """Return the botocore Error dict; an unexpected SUCCESS raises rather than returning a falsy
    sentinel (the bar's cited correct form)."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}"
    )


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not reached within {timeout_s}s; last observation {last!r}"
            )
        time.sleep(interval_s)
        last = probe()
    return last


def _smtp_password(secret_access_key: str, region: str) -> str:
    """https://docs.aws.amazon.com/ses/latest/dg/smtp-credentials.html"""

    def _sign(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    signature = _sign(("AWS4" + secret_access_key).encode("utf-8"), _DERIVE_DATE)
    for element in (region, _DERIVE_SERVICE, "aws4_request", _DERIVE_TERMINAL):
        signature = _sign(signature, element)
    return base64.b64encode(bytes([_DERIVE_VERSION]) + signature).decode("ascii")


def _delete_user_verified(iam, user: str, policy: str) -> None:
    try:
        for meta in iam.list_access_keys(UserName=user)["AccessKeyMetadata"]:
            iam.delete_access_key(UserName=user, AccessKeyId=meta["AccessKeyId"])
        iam.delete_user_policy(UserName=user, PolicyName=policy)
        iam.delete_user(UserName=user)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
            return
        print(f"LEAK: could not tear down IAM user {user}")
        raise
    try:
        iam.get_user(UserName=user)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
            return
        raise
    print(f"LEAK: IAM user {user} still present after delete_user")
    raise AssertionError(f"IAM user {user} still present after delete_user")


def _authed(host, port, access_key_id, password, attempts=30, delay=5.0):
    """Open a TLS session and AUTH, with a bounded retry on 535; RAISES on exhaustion."""
    last = None
    for _ in range(attempts):
        smtp = smtplib.SMTP_SSL(
            host, port, timeout=30, context=ssl._create_unverified_context()
        )
        smtp.ehlo()
        try:
            code, message = smtp.login(access_key_id, password)
        except smtplib.SMTPAuthenticationError as exc:
            last = (exc.smtp_code, exc.smtp_error)
            smtp.close()
            time.sleep(delay)
            continue
        assert (code, message) == (235, b"Authentication successful."), (
            f"AUTH with the correctly derived password answered {(code, message)!r}, expected "
            f"(235, b'Authentication successful.')"
        )
        return smtp
    raise AssertionError(
        f"the correctly derived SMTP password never authenticated on {host}:{port} in {attempts} "
        f"attempts; the last refusal was {last!r}"
    )


def _smtp_verdict(host, port, access_key_id, password, sender) -> tuple[str, int, str]:
    """Drive one full SMTP transaction and return (phase, code, text) for the FIRST reply that is
    not a success. Returning the PHASE as well as the code is what lets the paused and baseline
    refusals be compared without pre-committing to which phase SES refuses in — an
    unverified sender is refused at end-of-DATA, but nothing documents where an
    account-level pause is refused, and guessing it would be a literal dressed as a contract."""
    smtp = _authed(host, port, access_key_id, password)
    try:
        code, raw = smtp.docmd("MAIL", f"FROM:<{sender}>")
        if code != 250:
            return "MAIL", code, raw.decode("ascii", "replace")
        code, raw = smtp.docmd("RCPT", f"TO:<{_RECIPIENT}>")
        if code != 250:
            return "RCPT", code, raw.decode("ascii", "replace")
        code, raw = smtp.docmd("DATA")
        if code != 354:
            return "DATA", code, raw.decode("ascii", "replace")
        smtp.send(
            f"From: {sender}\r\nTo: {_RECIPIENT}\r\n"
            f"Subject: sim2real account-pause probe\r\n\r\nprobe\r\n.\r\n".encode()
        )
        code, raw = smtp.getreply()
        return "END-OF-DATA", code, raw.decode("ascii", "replace")
    finally:
        try:
            smtp.quit()
        except smtplib.SMTPException:
            smtp.close()


@tags(
    "axis:rejection",
    "cap:c1",
    "cap:c6",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:native",
    "plane:data",
    "resource:account-singleton:ses-account",
)
def run(ctx) -> None:
    """With an unverified sender, the account sending pause outranks the identity gate on both front
    doors: the API answers AccountSendingPausedException where it answered MessageRejected, the SMTP refusal
    differs from its baseline and reverts to it on re-enable, and GetSendStatistics is unchanged."""
    iam = ctx.client("iam")
    ses = ctx.client("ses")
    host, port = ctx.service_host(f"email-smtp.{ctx.region}.amazonaws.com", _SMTP_PORT)

    user = ctx.unique_name("sim2real-behav-ses-pause-smtp-")
    policy = "sim2real-ses-send-raw-email"
    iam.create_user(UserName=user, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_user_verified(iam, user, policy))
    iam.put_user_policy(
        UserName=user,
        PolicyName=policy,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": ["ses:SendRawEmail"], "Resource": "*"}
                ],
            }
        ),
    )
    key = iam.create_access_key(UserName=user)["AccessKey"]
    access_key_id, secret = key["AccessKeyId"], key["SecretAccessKey"]
    password = _smtp_password(secret, ctx.region)

    sender_domain = ctx.unique_name("sim2real-behav-pause-") + ".example.com"
    sender = f"noreply@{sender_domain}"  # RFC 2606 reserved TLD: never a real mailbox.

    # The message of the latest API refusal, asserted next to its code.
    last_api_error = {"Message": None}
    identity_refusal = (
        f"Email address is not verified. The following identities failed the check in region "
        f"{ctx.region.upper()}: {sender}"
    )

    def _api_send_code() -> str:
        err = _client_error(
            lambda: ses.send_email(
                Source=sender,
                Destination={"ToAddresses": [_RECIPIENT]},
                Message={
                    "Subject": {"Data": "sim2real account-pause probe"},
                    "Body": {"Text": {"Data": "This send must be refused."}},
                },
            )
        )
        last_api_error["Message"] = err.get("Message")
        return err.get("Code") or ""

    stats_before = ses.get_send_statistics()["SendDataPoints"]

    # --- Beat 1, positive control on both front doors while the account is HEALTHY. This is what
    #     stops the check from passing merely because everything is refused.
    assert ses.get_account_sending_enabled()["Enabled"] is True, (
        "setup precondition: account-level sending must start ENABLED, or the baseline arm is "
        "measuring the paused state and the whole comparison inverts"
    )
    api_baseline = _api_send_code()
    assert api_baseline == "MessageRejected", (
        f"with sending enabled, an unverified source must be refused by the IDENTITY gate: "
        f"expected MessageRejected, got {api_baseline!r}"
    )
    assert last_api_error["Message"] == identity_refusal, (
        f"expected {identity_refusal!r}, got {last_api_error['Message']!r}"
    )
    smtp_baseline = _poll(
        lambda: _smtp_verdict(host, port, access_key_id, password, sender),
        lambda v: v[0] == "END-OF-DATA" and v[1] == 554 and v[2].startswith(_BASELINE_PREFIX),
        timeout_s=60,
        interval_s=5,
        description=(
            "the SMTP listener answers the unverified-sender baseline refusal once the freshly "
            "minted SMTP credential has propagated to the frontend serving this connection"
        ),
    )
    assert smtp_baseline[0] == "END-OF-DATA" and smtp_baseline[1] == 554, (
        f"with sending enabled, the SMTP listener must defer the unverified-sender refusal to "
        f"end-of-DATA with 554; got "
        f"{smtp_baseline!r}"
    )
    assert smtp_baseline[2].startswith(_BASELINE_PREFIX), (
        f"the baseline SMTP refusal must be the unverified-sender one; expected it to open with "
        f"{_BASELINE_PREFIX!r}, got {smtp_baseline[2]!r}"
    )

    # --- Beat 2, break exactly one thing. The restore is registered FIRST: this is an
    #     account-global singleton and a mid-check failure must not leave the account paused.
    ctx.on_cleanup(lambda: ses.update_account_sending_enabled(Enabled=True))
    ses.update_account_sending_enabled(Enabled=False)
    paused_flag = _poll(
        lambda: ses.get_account_sending_enabled()["Enabled"],
        lambda v: v is False,
        timeout_s=60,
        interval_s=2,
        description="GetAccountSendingEnabled reflects the paused state",
    )
    assert paused_flag is False, (
        f"the pause must be observably stored before anything is concluded from its effect; "
        f"GetAccountSendingEnabled reported {paused_flag!r}"
    )

    # --- Beat 3, the API front door: the pause OUTRANKS the identity gate.
    api_paused = _poll(
        _api_send_code,
        lambda c: c == "AccountSendingPausedException",
        timeout_s=60,
        interval_s=5,
        description=(
            "the API front door refuses with AccountSendingPausedException once sending is paused"
        ),
    )
    assert api_paused == "AccountSendingPausedException", (
        f"while sending is paused, the SAME unverified-source send must be refused for the "
        f"ACCOUNT reason, not the identity reason: expected AccountSendingPausedException, got "
        f"{api_paused!r}"
    )
    assert last_api_error["Message"] == "Sending is paused for this account.", (
        f"expected 'Sending is paused for this account.', got {last_api_error['Message']!r}"
    )
    assert api_paused != api_baseline, (
        f"the paused refusal must differ from the enabled refusal, or the account flag is not "
        f"being consulted at all; both answered {api_baseline!r}"
    )

    # --- Beat 4, the SMTP front door on the same wiring, at the same moment. The SMTP fleet is
    #     separate from the API front door and may see the pause later, so this polls rather than
    #     reading once (measured on real AWS: the API side can flip before the SMTP side does).
    smtp_paused = _poll(
        lambda: _smtp_verdict(host, port, access_key_id, password, sender),
        lambda v: v != smtp_baseline and v[1] >= 400,
        timeout_s=60,
        interval_s=5,
        description=(
            "the SMTP listener's verdict changes once the account-level pause reaches the SMTP "
            "fleet"
        ),
    )
    assert smtp_paused[1] >= 400, (
        f"while sending is paused, the SMTP listener must REFUSE the transaction somewhere; got "
        f"{smtp_paused!r}"
    )
    assert smtp_paused != smtp_baseline, (
        f"the SMTP refusal must change when the account is paused — a listener that answers the "
        f"unverified-sender refusal regardless is not reading account state; both runs answered "
        f"{smtp_baseline!r}"
    )
    assert not smtp_paused[2].startswith(_BASELINE_PREFIX), (
        f"the paused SMTP refusal must not be the unverified-sender message; got {smtp_paused!r}"
    )

    # --- Beat 5, restore: re-enable and prove the flag is observably back.
    ses.update_account_sending_enabled(Enabled=True)
    enabled_flag = _poll(
        lambda: ses.get_account_sending_enabled()["Enabled"],
        lambda v: v is True,
        timeout_s=60,
        interval_s=2,
        description="GetAccountSendingEnabled reflects the re-enabled state",
    )
    assert enabled_flag is True, (
        f"the pause must be observably lifted; GetAccountSendingEnabled reported {enabled_flag!r}"
    )

    # --- Beat 6, terminal independent reads at the destination: the API refusal reverts to the
    #     identity gate, and the SMTP listener reverts to the byte-identical baseline reply. The
    #     revert is what makes the pause the cause rather than a coincidence.
    api_restored = _poll(
        _api_send_code,
        lambda c: c == "MessageRejected",
        timeout_s=60,
        interval_s=5,
        description="the API front door reverts to the identity gate once sending is re-enabled",
    )
    assert api_restored == api_baseline, (
        f"after re-enabling, the identical send must be refused for the identity reason again: "
        f"expected {api_baseline!r}, got {api_restored!r}"
    )
    assert last_api_error["Message"] == identity_refusal, (
        f"expected {identity_refusal!r}, got {last_api_error['Message']!r}"
    )
    smtp_restored = _poll(
        lambda: _smtp_verdict(host, port, access_key_id, password, sender),
        lambda v: v == smtp_baseline,
        timeout_s=60,
        interval_s=5,
        description=(
            "the SMTP listener reverts to the baseline refusal once the re-enable reaches the "
            "SMTP fleet — measured to lag the API front door's own GetAccountSendingEnabled"
        ),
    )
    assert smtp_restored == smtp_baseline, (
        f"after re-enabling, the SMTP listener must answer the byte-identical baseline refusal: "
        f"expected {smtp_baseline!r}, got {smtp_restored!r}"
    )

    # --- Effect absent on an independent side-channel: six refusals, no delivery attempts.
    stats_after = ses.get_send_statistics()["SendDataPoints"]
    assert stats_after == stats_before, (
        f"GetSendStatistics moved from {stats_before!r} to {stats_after!r}; every send in this "
        f"check was refused and none may be counted as a delivery attempt"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
