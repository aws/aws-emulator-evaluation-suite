"""v1-v2-shared-store-account-config-set-and-identity-policy."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "v1-v2-shared-store-account-config-set-and-identity-policy"
GROUP = "shared-state-v1-v2"
SERVICES = ["ses", "sesv2"]

_SIMULATOR_TO = "success@simulator.amazonses.com"


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """The (Error.Code, Error.Message) ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not reached within {timeout_s}s; last observation {last!r}")
        time.sleep(interval_s)
        last = probe()
    return last


def _identity_policy(ctx, identity: str, sid: str) -> str:
    return json.dumps(
        {
            "Version": "2008-10-17",
            "Statement": [
                {
                    "Sid": sid,
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
                    "Action": "ses:SendEmail",
                    "Resource": f"arn:aws:ses:{ctx.region}:{ctx.account}:identity/{identity}",
                }
            ],
        }
    )


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
    "resource:account-singleton:ses-account",
)
def run(ctx) -> None:
    """Account sending, a configuration set's sending flag and an identity's policies are one
    store: a write from either SESv1 or SESv2 is read back through the other, and a policy
    created through one API is deleted through the other and is then absent from both.

    Reference: https://docs.aws.amazon.com/ses/latest/dg/sending-authorization.html
    """
    v1 = ctx.client("ses")
    v2 = ctx.client("sesv2")

    # ---- account sending: one flag per account, flipped from v1, read from v2, restored from v2 ----
    original_enabled = v1.get_account_sending_enabled()["Enabled"]
    toggled_enabled = not original_enabled

    v1.update_account_sending_enabled(Enabled=toggled_enabled)
    ctx.on_cleanup(lambda: v1.update_account_sending_enabled(Enabled=original_enabled))

    seen_by_v2 = _poll(
        lambda: v2.get_account()["SendingEnabled"],
        lambda v: v == toggled_enabled,
        timeout_s=60,
        interval_s=2,
        description="GetAccount reflects the v1 UpdateAccountSendingEnabled write",
    )
    assert seen_by_v2 == toggled_enabled, (
        f"expected v2 GetAccount SendingEnabled {toggled_enabled!r} after the v1 write, got {seen_by_v2!r}"
    )

    v2.put_account_sending_attributes(SendingEnabled=original_enabled)
    seen_by_v1 = _poll(
        lambda: v1.get_account_sending_enabled()["Enabled"],
        lambda v: v == original_enabled,
        timeout_s=60,
        interval_s=2,
        description="GetAccountSendingEnabled reflects the v2 PutAccountSendingAttributes restore",
    )
    assert seen_by_v1 == original_enabled, (
        f"expected v1 GetAccountSendingEnabled {original_enabled!r} after the v2 restore, got {seen_by_v1!r}"
    )

    # ---- configuration set sending: v2 can read it directly; v1 only exposes it through SendEmail ----
    cs_name = ctx.unique_name("sim2real-behav-cssend-")
    v2.create_configuration_set(ConfigurationSetName=cs_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(_teardown(lambda: v2.delete_configuration_set(ConfigurationSetName=cs_name), "NotFoundException"))

    sender = f"{ctx.unique_name('sim2real-behav-cssend-sender-')}@example.com"
    identity_refusal = (
        f"Email address is not verified. The following identities failed the check in region "
        f"{ctx.region.upper()}: {sender}"
    )
    paused_refusal = f"Sending is paused for configuration set {cs_name}"

    def _probe_send():
        return _error(
            lambda: v1.send_email(
                Source=sender,
                Destination={"ToAddresses": [_SIMULATOR_TO]},
                Message={"Subject": {"Data": "probe"}, "Body": {"Text": {"Data": "probe"}}},
                ConfigurationSetName=cs_name,
            )
        )

    v1.update_configuration_set_sending_enabled(ConfigurationSetName=cs_name, Enabled=False)
    seen_by_v2_cs = _poll(
        lambda: v2.get_configuration_set(ConfigurationSetName=cs_name)["SendingOptions"]["SendingEnabled"],
        lambda v: v is False,
        timeout_s=60,
        interval_s=2,
        description="GetConfigurationSet reflects the v1 UpdateConfigurationSetSendingEnabled(False) write",
    )
    assert seen_by_v2_cs is False, f"expected v2 SendingOptions.SendingEnabled False, got {seen_by_v2_cs!r}"

    paused_code, paused_msg = _poll(
        _probe_send,
        lambda cm: cm[0] == "ConfigurationSetSendingPausedException",
        timeout_s=60,
        interval_s=5,
        description="SendEmail is refused for the configuration set once v1 disables its sending",
    )
    assert paused_code == "ConfigurationSetSendingPausedException", (
        f"expected ConfigurationSetSendingPausedException, got {paused_code!r}: {paused_msg!r}"
    )
    assert paused_msg == paused_refusal, f"expected {paused_refusal!r}, got {paused_msg!r}"

    v2.put_configuration_set_sending_options(ConfigurationSetName=cs_name, SendingEnabled=True)
    resumed_code, resumed_msg = _poll(
        _probe_send,
        lambda cm: cm[0] != "ConfigurationSetSendingPausedException",
        timeout_s=60,
        interval_s=5,
        description="SendEmail stops citing the configuration set once v2 re-enables its sending",
    )
    assert resumed_code == "MessageRejected", (
        f"expected v1 to fall through to the identity gate (MessageRejected) once v2 re-enabled "
        f"the configuration set, got {resumed_code!r}: {resumed_msg!r}"
    )
    assert resumed_msg == identity_refusal, f"expected {identity_refusal!r}, got {resumed_msg!r}"

    # ---- identity authorization policies: one map, created via one API and deleted via the other ----
    identity = f"{ctx.unique_name('sim2real-behav-idpol-')}@example.com"
    v1.verify_email_identity(EmailAddress=identity)
    ctx.on_cleanup(lambda: v1.delete_identity(Identity=identity))

    pol_a = ctx.unique_name("sim2real-behav-pola-")
    pol_b = ctx.unique_name("sim2real-behav-polb-")
    doc_a = _identity_policy(ctx, identity, "a")
    doc_b = _identity_policy(ctx, identity, "b")

    v1.put_identity_policy(Identity=identity, PolicyName=pol_a, Policy=doc_a)
    ctx.on_cleanup(_teardown(lambda: v1.delete_identity_policy(Identity=identity, PolicyName=pol_a)))

    names = v1.list_identity_policies(Identity=identity)["PolicyNames"]
    assert names == [pol_a], f"expected v1 ListIdentityPolicies to list exactly [{pol_a!r}], got {names!r}"

    v2_policies = v2.get_email_identity_policies(EmailIdentity=identity)["Policies"]
    assert set(v2_policies) == {pol_a}, f"expected v2 Policies keys {{{pol_a!r}}}, got {set(v2_policies)!r}"
    assert json.loads(v2_policies[pol_a]) == json.loads(doc_a), (
        f"v2 GetEmailIdentityPolicies returned a document for {pol_a!r} that differs from the one "
        f"v1 PutIdentityPolicy wrote: {v2_policies[pol_a]!r}"
    )

    v2.create_email_identity_policy(EmailIdentity=identity, PolicyName=pol_b, Policy=doc_b)
    ctx.on_cleanup(
        _teardown(lambda: v2.delete_email_identity_policy(EmailIdentity=identity, PolicyName=pol_b), "NotFoundException")
    )

    names_both = v1.list_identity_policies(Identity=identity)["PolicyNames"]
    assert sorted(names_both) == sorted([pol_a, pol_b]), (
        f"expected v1 ListIdentityPolicies to list exactly {{{pol_a!r}, {pol_b!r}}}, got {names_both!r}"
    )
    v2_policies_both = v2.get_email_identity_policies(EmailIdentity=identity)["Policies"]
    assert set(v2_policies_both) == {pol_a, pol_b}, (
        f"expected v2 Policies keys {{{pol_a!r}, {pol_b!r}}}, got {set(v2_policies_both)!r}"
    )

    # The policy v1 created is deleted through v2, and disappears from both.
    v2.delete_email_identity_policy(EmailIdentity=identity, PolicyName=pol_a)
    names_after_v2_delete = v1.list_identity_policies(Identity=identity)["PolicyNames"]
    assert names_after_v2_delete == [pol_b], (
        f"expected v1 to list exactly [{pol_b!r}] after v2 deleted {pol_a!r}, got {names_after_v2_delete!r}"
    )
    v2_policies_after_v2_delete = v2.get_email_identity_policies(EmailIdentity=identity)["Policies"]
    assert set(v2_policies_after_v2_delete) == {pol_b}, (
        f"expected v2 Policies keys {{{pol_b!r}}} after deleting {pol_a!r}, got "
        f"{set(v2_policies_after_v2_delete)!r}"
    )

    # The policy v2 created is deleted through v1, and disappears from both.
    v1.delete_identity_policy(Identity=identity, PolicyName=pol_b)
    names_after_v1_delete = v1.list_identity_policies(Identity=identity)["PolicyNames"]
    assert names_after_v1_delete == [], (
        f"expected v1 ListIdentityPolicies to be empty after v1 deleted {pol_b!r}, got {names_after_v1_delete!r}"
    )
    v2_policies_after_v1_delete = v2.get_email_identity_policies(EmailIdentity=identity)["Policies"]
    assert v2_policies_after_v1_delete == {}, (
        f"expected v2 Policies to be empty after v1 deleted {pol_b!r}, got {v2_policies_after_v1_delete!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
