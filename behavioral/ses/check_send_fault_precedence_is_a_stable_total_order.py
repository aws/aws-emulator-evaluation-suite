"""send-fault-precedence-is-a-stable-total-order."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-fault-precedence-is-a-stable-total-order"
GROUP = "sending"
SERVICES = ["ses"]

# The mailbox simulator's `success@` address: a simulated bounce or complaint would count against
# the account's reputation. Every send below is expected to be refused anyway.
_SIMULATOR_TO = "success@simulator.amazonses.com"


def _client_error(fn) -> dict:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}"
    )


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


def _paused(err: dict) -> bool:
    """Whether a refusal is the one a paused account answers instead of the graded rung."""
    return err.get("Code") == _PAUSED_CODE["ses"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """SendEmail reports faults in a fixed order (ValidationError, ConfigurationSetDoesNotExist,
    MessageRejected), repairing one reveals the next, the ladder repeats on a second pass,
    SendRawEmail agrees on the last two rungs, and no refused call moves the send quota.

    Reference: https://docs.aws.amazon.com/ses/latest/APIReference/API_SendEmail.html
    """
    ses = ctx.client("ses")

    sender = f"{ctx.unique_name('sim2real-behav-precedence-')}@example.com"
    ses.verify_email_identity(EmailAddress=sender)
    ctx.on_cleanup(lambda: ses.delete_identity(Identity=sender))
    attrs = ses.get_identity_verification_attributes(Identities=[sender])[
        "VerificationAttributes"
    ]
    assert attrs[sender]["VerificationStatus"] == "Pending", (
        f"setup precondition: the sender must be a real identity that is simply not verified, so "
        f"the identity gate is armed rather than absent; got {attrs[sender]!r}"
    )

    config_set = ctx.unique_name("sim2real-behav-precedence-cs-")
    null_destination_msg = (
        "1 validation error detected: Value at 'destination' failed to satisfy constraint: "
        "Member must not be null"
    )
    unverified_msg = (
        "Email address is not verified. The following identities failed the check in region "
        f"{ctx.region.upper()}: {sender}"
    )

    def _missing_set_msg(name: str) -> str:
        return f"Configuration set <{name}> does not exist."

    def _past_set_lookup(send, *, timeout_s=90, interval_s=3):
        """Repeat a send that names the just-created configuration set until the send path
        stops reporting that set missing (a new set reaches the send path after a short lag);
        RAISES on the deadline, so a set that never becomes visible fails loudly."""
        deadline = time.monotonic() + timeout_s
        while True:
            err = send()
            if err.get("Code") != "ConfigurationSetDoesNotExist":
                return err
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"the send path still reports {config_set!r} missing {timeout_s}s after "
                    f"CreateConfigurationSet; last refusal {err!r}"
                )
            time.sleep(interval_s)

    quota_before = ses.get_send_quota()["SentLast24Hours"]

    def _refused(send, own_code: str, lagging: bool) -> dict:
        """The Error dict of a refused send: ``own_code``, or the paused refusal while the
        account's sending is paused; ``lagging`` also admits a just-created set read as missing."""
        exc, allowed = _send_refusal(ctx, "ses", send, own_code)
        if lagging:
            allowed.add("ConfigurationSetDoesNotExist")
        assert exc is not None, "real AWS refuses this send, but it SUCCEEDED"
        err = exc.response.get("Error", {})
        assert err.get("Code") in allowed, (
            f"expected {sorted(allowed)}, got {err.get('Code')!r}: {err.get('Message')!r}"
        )
        return err

    def _send(destination: dict, configuration_set: str, own_code: str, lagging=False) -> dict:
        return _refused(
            lambda: ses.send_email(
                Source=sender,
                Destination=destination,
                ConfigurationSetName=configuration_set,
                Message={
                    "Subject": {"Data": "sim2real send-fault precedence probe"},
                    "Body": {"Text": {"Data": "This send must be refused."}},
                },
            ),
            own_code,
            lagging,
        )

    def _send_raw(destinations: list[str], configuration_set: str, own_code: str, lagging=False) -> dict:
        raw = (
            f"From: {sender}\r\n"
            f"To: {_SIMULATOR_TO}\r\n"
            "Subject: sim2real send-fault precedence probe\r\n"
            "MIME-Version: 1.0\r\n"
            "Content-Type: text/plain; charset=UTF-8\r\n"
            "\r\n"
            "This send must be refused.\r\n"
        )
        return _refused(
            lambda: ses.send_raw_email(
                Source=sender,
                Destinations=destinations,
                RawMessage={"Data": raw.encode("utf-8")},
                ConfigurationSetName=configuration_set,
            ),
            own_code,
            lagging,
        )

    # The ladder is walked by repairing exactly one fault per rung:
    #   Rung 1: Destination malformed + configuration set absent + Source unverified.
    #   Rung 2: Destination repaired. Configuration set still absent, Source still unverified.
    #   Rung 3: configuration set created. Source still unverified: this is the floor, because
    #           verifying an identity needs an email click-through or a DNS record.
    #
    # --- Pass 1, rungs 1 and 2: everything broken, then only the Destination repaired.
    rung1 = _send({}, config_set, "ValidationError")
    assert rung1.get("Code") == "ValidationError" or _paused(rung1), (
        f"with a malformed Destination, an unknown configuration set AND an unverified Source, "
        f"structural validation must win: expected ValidationError, got {rung1.get('Code')!r}: "
        f"{rung1.get('Message')!r}"
    )
    assert _paused(rung1) or rung1.get("Message") == null_destination_msg, (
        f"expected {null_destination_msg!r}, got {rung1.get('Message')!r}"
    )
    rung2 = _send({"ToAddresses": [_SIMULATOR_TO]}, config_set, "ConfigurationSetDoesNotExist")
    assert rung2.get("Code") == "ConfigurationSetDoesNotExist" or _paused(rung2), (
        f"repairing ONLY the Destination must advance the answer to the configuration-set lookup: "
        f"expected ConfigurationSetDoesNotExist, got {rung2.get('Code')!r}: "
        f"{rung2.get('Message')!r}"
    )
    assert _paused(rung2) or rung2.get("Message") == _missing_set_msg(config_set), (
        f"the configuration-set refusal must name the set it could not find, {config_set!r}; got "
        f"{rung2.get('Message')!r}"
    )

    # --- Rung 3: create ONLY the configuration set. The Source stays unverified.
    ses.create_configuration_set(ConfigurationSet={"Name": config_set})
    ctx.on_cleanup(lambda: ses.delete_configuration_set(ConfigurationSetName=config_set))
    assert (
        ses.describe_configuration_set(ConfigurationSetName=config_set)["ConfigurationSet"]["Name"]
        == config_set
    ), (
        f"the configuration set must be observably real before anything is concluded from the "
        f"answer changing; DescribeConfigurationSet did not return {config_set!r}"
    )
    rung3 = _past_set_lookup(
        lambda: _send({"ToAddresses": [_SIMULATOR_TO]}, config_set, "MessageRejected", True)
    )
    assert rung3.get("Code") == "MessageRejected" or _paused(rung3), (
        f"with structure and configuration set both repaired, the only remaining fault is the "
        f"unverified Source: expected MessageRejected, got {rung3.get('Code')!r}: "
        f"{rung3.get('Message')!r}"
    )
    assert _paused(rung3) or rung3.get("Message") == unverified_msg, (
        f"MessageRejected must name the identity that failed the gate, {sender!r}; got "
        f"{rung3.get('Message')!r}"
    )

    first_pass = [rung1.get("Code"), rung2.get("Code"), rung3.get("Code")]
    # A rung answered by the paused refusal graded only its code; the ladder is graded without it.
    assert any(map(_paused, (rung1, rung2, rung3))) or len(set(first_pass)) == 3, (
        f"each repair must CHANGE the answer — three distinct codes are what separates a real "
        f"evaluation order from one constant refusal; got {first_pass!r}"
    )

    # --- Pass 2, stability: the identical ladder, now that the configuration set exists, must be
    #     reproducible from rung 1.
    stable1 = _send({}, config_set, "ValidationError")
    assert stable1.get("Code") == "ValidationError" or _paused(stable1), (
        f"a malformed Destination must still win even though the configuration set now exists — "
        f"the order is a property of the request, not of what happens to be missing; expected "
        f"ValidationError, got {stable1.get('Code')!r}: {stable1.get('Message')!r}"
    )
    assert _paused(stable1) or stable1.get("Message") == null_destination_msg, (
        f"expected {null_destination_msg!r}, got {stable1.get('Message')!r}"
    )
    ghost_set = ctx.unique_name("sim2real-behav-precedence-ghost-cs-")
    stable2 = _send({"ToAddresses": [_SIMULATOR_TO]}, ghost_set, "ConfigurationSetDoesNotExist")
    assert stable2.get("Code") == "ConfigurationSetDoesNotExist" or _paused(stable2), (
        f"a second, never-created configuration set must reproduce rung 2: expected "
        f"ConfigurationSetDoesNotExist, got {stable2.get('Code')!r}: {stable2.get('Message')!r}"
    )
    assert _paused(stable2) or stable2.get("Message") == _missing_set_msg(ghost_set), (
        f"the second configuration-set refusal must name ITS own missing set {ghost_set!r} — two "
        f"different absent sets must not collapse into one canned message; got "
        f"{stable2.get('Message')!r}"
    )
    stable3 = _send({"ToAddresses": [_SIMULATOR_TO]}, config_set, "MessageRejected")
    assert _paused(stable3) or stable3.get("Message") == unverified_msg, (
        f"expected {unverified_msg!r} on the second pass, got {stable3.get('Message')!r}"
    )
    second_pass = (rung1, rung2, rung3, stable1, stable2, stable3)
    assert any(map(_paused, second_pass)) or [
        stable1.get("Code"), stable2.get("Code"), stable3.get("Code")
    ] == first_pass, (
        f"the ladder must be stable: pass 1 saw {first_pass!r}, pass 2 saw "
        f"{[stable1.get('Code'), stable2.get('Code'), stable3.get('Code')]!r}"
    )

    # --- SendRawEmail must agree on the last two rungs. Structural validation differs between the
    #     two operations (SendRawEmail may take its recipients from the MIME headers, so an empty
    #     Destinations list is not necessarily malformed), so rung 1 is not asserted for it.
    raw_ghost = _send_raw([_SIMULATOR_TO], ghost_set, "ConfigurationSetDoesNotExist")
    assert raw_ghost.get("Code") == "ConfigurationSetDoesNotExist" or _paused(raw_ghost), (
        f"SendRawEmail must share the ladder: an unknown configuration set outranks an unverified "
        f"Source. Expected ConfigurationSetDoesNotExist, got {raw_ghost.get('Code')!r}: "
        f"{raw_ghost.get('Message')!r}"
    )
    assert _paused(raw_ghost) or raw_ghost.get("Message") == _missing_set_msg(ghost_set), (
        f"expected {_missing_set_msg(ghost_set)!r}, got {raw_ghost.get('Message')!r}"
    )
    raw_rejected = _past_set_lookup(
        lambda: _send_raw([_SIMULATOR_TO], config_set, "MessageRejected", True)
    )
    assert raw_rejected.get("Code") == "MessageRejected" or _paused(raw_rejected), (
        f"with a real configuration set, SendRawEmail must land on the identity gate exactly as "
        f"SendEmail does. Expected MessageRejected, got {raw_rejected.get('Code')!r}: "
        f"{raw_rejected.get('Message')!r}"
    )
    assert _paused(raw_rejected) or raw_rejected.get("Message") == unverified_msg, (
        f"expected {unverified_msg!r}, got {raw_rejected.get('Message')!r}"
    )
    assert any(map(_paused, (rung2, rung3, raw_ghost, raw_rejected))) or [
        raw_ghost.get("Code"), raw_rejected.get("Code")
    ] == first_pass[1:], (
        f"the two send operations must not implement different ladders: SendEmail saw "
        f"{first_pass[1:]!r}, SendRawEmail saw "
        f"{[raw_ghost.get('Code'), raw_rejected.get('Code')]!r}"
    )

    # --- Effect absent, by independent reads through different operations: none of the refused
    #     calls was a send, and none of them verified the sender.
    quota_after = ses.get_send_quota()["SentLast24Hours"]
    assert quota_after - quota_before < 1.0, (
        f"none of the refused calls may be counted as a send: GetSendQuota.SentLast24Hours moved "
        f"{quota_before} -> {quota_after}"
    )
    final_attrs = ses.get_identity_verification_attributes(Identities=[sender])[
        "VerificationAttributes"
    ]
    assert final_attrs[sender]["VerificationStatus"] == "Pending", (
        f"a refused send must not verify its Source; expected Pending, got "
        f"{final_attrs[sender]!r}"
    )
    # The created set still exists, and the ghost set was not created by being named in a send.
    assert (
        ses.describe_configuration_set(ConfigurationSetName=config_set)["ConfigurationSet"]["Name"]
        == config_set
    ), f"terminal read: the created configuration set {config_set!r} must still be describable"
    ghost_read = _client_error(
        lambda: ses.describe_configuration_set(ConfigurationSetName=ghost_set)
    )
    assert ghost_read.get("Code") == "ConfigurationSetDoesNotExist", (
        f"a refused send must not create the configuration set it complained about; "
        f"DescribeConfigurationSet({ghost_set!r}) answered {ghost_read!r}"
    )
    assert ghost_read.get("Message") == _missing_set_msg(ghost_set), (
        f"expected {_missing_set_msg(ghost_set)!r}, got {ghost_read.get('Message')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
