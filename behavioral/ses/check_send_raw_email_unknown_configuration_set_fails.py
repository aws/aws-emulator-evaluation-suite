"""send-raw-email-unknown-configuration-set-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-raw-email-unknown-configuration-set-fails"
GROUP = 'overly-permissive'
SERVICES = ['ses']

def _err(fn):
    """Call fn(); return the (Code, Message) of the ClientError it raises; raise if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _unique_email(ctx, prefix="probe-"):
    return f"{ctx.unique_name('sim2real-behav-' + prefix)}@example.com"


# The refusal a send meets while the account's sending is paused, per API.
_PAUSED_CODE = {"ses": "AccountSendingPausedException", "sesv2": "SendingPausedException"}


def _send_refusal(ctx, api: str, send, own_code: str):
    """Run ``send`` between two GetAccountSendingEnabled reads; return its ClientError (None on
    success) and the codes it may carry: ``own_code`` while sending is enabled, the paused refusal
    while it is paused, and either when the state changes in between."""
    account = ctx.client("ses")
    before = account.get_account_sending_enabled()["Enabled"]
    try:
        send()
        err = None
    except ClientError as exc:
        err = exc
    after = account.get_account_sending_enabled()["Enabled"]
    return err, {own_code if enabled else _PAUSED_CODE[api] for enabled in (before, after)}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendRawEmail naming a nonexistent configuration set fails with ConfigurationSetDoesNotExist
    ahead of the Pending-sender check, counts no send, and stops once that set is created."""
    ses = ctx.client("ses")
    email = _unique_email(ctx)
    ses.verify_email_identity(EmailAddress=email)
    ctx.on_cleanup(lambda _n=email: ses.delete_identity(Identity=_n))

    raw = (
        f"From: {email}\r\n"
        f"To: {email}\r\n"
        "Subject: probe\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/plain; charset=UTF-8\r\n"
        "\r\n"
        "probe body\r\n"
    ).encode("utf-8")

    def _send(cs_name, own_code):
        """The send's (Code, Message); the code is ``own_code``, or the paused refusal while sending is
        paused."""
        exc, allowed = _send_refusal(
            ctx,
            "ses",
            lambda: ses.send_raw_email(
                Source=email,
                Destinations=[email],
                RawMessage={"Data": raw},
                ConfigurationSetName=cs_name,
            ),
            own_code,
        )
        assert exc is not None, f"expected SendRawEmail with {cs_name!r} to be refused, but it succeeded"
        error = exc.response.get("Error", {})
        code = error.get("Code")
        assert code in allowed, f"expected {sorted(allowed)}, got {code!r}: {error.get('Message')!r}"
        return code, error.get("Message")

    sent_before = ses.get_send_quota()["SentLast24Hours"]

    # With a real configuration set the same call hits the Pending-sender rejection instead.
    real_cs = ctx.unique_name("sim2real-behav-cfgset-real-")
    ses.create_configuration_set(ConfigurationSet={"Name": real_cs})
    ctx.on_cleanup(lambda _n=real_cs: ses.delete_configuration_set(ConfigurationSetName=_n))
    rejected_unverified = (
        "MessageRejected",
        "Email address is not verified. The following identities failed the check in region "
        f"{ctx.region.upper()}: {email}",
    )
    control_err = _send(real_cs, "MessageRejected")
    assert control_err == rejected_unverified or control_err[0] == _PAUSED_CODE["ses"], (
        f"a REAL configuration set must not raise ConfigurationSetDoesNotExist -- the identity gate "
        f"(this sender is Pending, never Success-verified) is the next thing in line; got {control_err!r}"
    )

    ghost_cs = ctx.unique_name("sim2real-behav-cfgset-ghost-")
    ghost_missing = ("ConfigurationSetDoesNotExist", f"Configuration set <{ghost_cs}> does not exist.")
    err = _send(ghost_cs, "ConfigurationSetDoesNotExist")
    assert err == ghost_missing or err[0] == _PAUSED_CODE["ses"], (
        f"expected ConfigurationSetDoesNotExist for an unknown configuration set, got {err!r}"
    )

    sent_after = ses.get_send_quota()["SentLast24Hours"]
    assert sent_after - sent_before < 1.0, (
        f"a rejected SendRawEmail must not move SentLast24Hours: {sent_before} -> {sent_after}"
    )
    describe_err = _err(lambda: ses.describe_configuration_set(ConfigurationSetName=ghost_cs))
    assert describe_err == ghost_missing, (
        f"the rejected call must not have created {ghost_cs!r}; describe returned {describe_err!r}"
    )

    ses.create_configuration_set(ConfigurationSet={"Name": ghost_cs})
    ctx.on_cleanup(lambda _n=ghost_cs: ses.delete_configuration_set(ConfigurationSetName=_n))
    restored_err = _send(ghost_cs, "MessageRejected")
    assert restored_err == rejected_unverified or restored_err[0] == _PAUSED_CODE["ses"], (
        f"after creating {ghost_cs!r}, the identical call must stop citing ConfigurationSetDoesNotExist "
        f"and fall through to the same identity gate the control hit; got {restored_err!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
