"""deleting-a-configuration-set-leaves-no-dangling-identity-default-reference."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deleting-a-configuration-set-leaves-no-dangling-identity-default-reference"
GROUP = "identity-v2"
SERVICES = ["sesv2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteConfigurationSet succeeds while an identity names the set as its default, the identity
    keeps the dead name (an unchecked string, inert and still clearable), and deleting an identity
    does not cascade into its default configuration set.
    """
    sesv2 = ctx.client("sesv2")

    config_set = _create_configuration_set(ctx, "cs-referenced-")
    identity = _create_identity(ctx)

    sesv2.put_email_identity_configuration_set_attributes(
        EmailIdentity=identity, ConfigurationSetName=config_set
    )
    associated = sesv2.get_email_identity(EmailIdentity=identity)
    assert associated.get("ConfigurationSetName") == config_set, (
        f"positive control: after PutEmailIdentityConfigurationSetAttributes, GetEmailIdentity("
        f"{identity}) reports ConfigurationSetName="
        f"{associated.get('ConfigurationSetName')!r}, expected {config_set!r}"
    )
    # The mutation used to show the dead name is unusable must first work while the set is alive.
    sesv2.put_configuration_set_sending_options(
        ConfigurationSetName=config_set, SendingEnabled=True
    )

    # DeleteConfigurationSet does not check for identity referrers: it succeeds unconditionally
    # rather than refusing with BadRequestException, the modelled candidate for "still in use".
    sesv2.delete_configuration_set(ConfigurationSetName=config_set)

    set_resolves = _resolves(lambda: sesv2.get_configuration_set(ConfigurationSetName=config_set))
    assert not set_resolves, (
        f"DeleteConfigurationSet({config_set}) returned success but GetConfigurationSet still "
        f"resolves it"
    )

    reference = sesv2.get_email_identity(EmailIdentity=identity).get("ConfigurationSetName")
    assert reference == config_set, (
        f"DeleteConfigurationSet({config_set}) cleared or refused the delete: GetEmailIdentity("
        f"{identity}) now reports ConfigurationSetName={reference!r}, but real AWS is measured to "
        f"leave the dangling reference {config_set!r} in place instead"
    )

    _assert_gone_and_unusable(sesv2, config_set)

    # The dangling field is an unchecked string, not a validated foreign key: it can still be
    # cleared even though the configuration set it names no longer exists.
    sesv2.put_email_identity_configuration_set_attributes(EmailIdentity=identity)
    cleared = sesv2.get_email_identity(EmailIdentity=identity).get("ConfigurationSetName")
    assert cleared is None, (
        f"after clearing, GetEmailIdentity({identity}) still reports "
        f"ConfigurationSetName={cleared!r}"
    )

    # The reverse direction: deleting the identity must not cascade into the configuration set.
    survivor = _create_configuration_set(ctx, "cs-survivor-")
    second_identity = _create_identity(ctx)
    sesv2.put_email_identity_configuration_set_attributes(
        EmailIdentity=second_identity, ConfigurationSetName=survivor
    )
    sesv2.delete_email_identity(EmailIdentity=second_identity)
    identity_code = _call_error_code(
        lambda: sesv2.get_email_identity(EmailIdentity=second_identity)
    )
    assert identity_code == (
        "NotFoundException",
        f"Email identity <{second_identity}> does not exist.",
    ), (
        f"after DeleteEmailIdentity, GetEmailIdentity({second_identity}) returned "
        f"{identity_code!r}, expected NotFoundException"
    )
    still_there = sesv2.get_configuration_set(ConfigurationSetName=survivor)
    assert still_there["ConfigurationSetName"] == survivor, (
        f"deleting email identity {second_identity} took its default configuration set "
        f"{survivor!r} with it: GetConfigurationSet returned {still_there!r}"
    )


def _create_configuration_set(ctx, prefix: str) -> str:
    sesv2 = ctx.client("sesv2")
    name = ctx.unique_name("sim2real-behav-" + prefix)
    sesv2.create_configuration_set(
        ConfigurationSetName=name,
        Tags=[
            {"Key": "sim2real-managed", "Value": "true"},
            {"Key": "sim2real-check", "Value": CHECK},
        ],
    )
    ctx.on_cleanup(lambda: _delete_if_present(sesv2, name))
    return name


def _create_identity(ctx) -> str:
    """An EMAIL_ADDRESS identity under the RFC 2606 reserved domain. It is never verified and
    nothing is ever sent from it — only its ConfigurationSetName field is the subject."""
    sesv2 = ctx.client("sesv2")
    address = ctx.unique_name("sim2real-behav-csref-") + "@example.com"
    sesv2.create_email_identity(
        EmailIdentity=address,
        Tags=[
            {"Key": "sim2real-managed", "Value": "true"},
            {"Key": "sim2real-check", "Value": CHECK},
        ],
    )
    ctx.on_cleanup(lambda: _delete_identity_if_present(sesv2, address))
    return address


def _delete_if_present(sesv2, name: str) -> None:
    try:
        sesv2.delete_configuration_set(ConfigurationSetName=name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise


def _delete_identity_if_present(sesv2, address: str) -> None:
    try:
        sesv2.delete_email_identity(EmailIdentity=address)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise


def _call_error_code(fn) -> tuple[str, str]:
    """The (Code, Message) of the ClientError fn() raises; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED: {result!r}")


def _resolves(fn) -> bool:
    try:
        fn()
    except ClientError as err:
        code = err.response["Error"]["Code"]
        if code == "NotFoundException":
            return False
        raise
    return True


def _assert_gone_and_unusable(sesv2, name: str) -> None:
    """An independent read returns the specific not-found code, and a mutation that worked
    earlier on this exact name now fails the same way."""
    missing = ("NotFoundException", f"Configuration set <{name}> does not exist.")
    read_code = _call_error_code(lambda: sesv2.get_configuration_set(ConfigurationSetName=name))
    assert read_code == missing, (
        f"GetConfigurationSet({name}) after deletion returned {read_code!r}, expected "
        f"NotFoundException"
    )
    mutate_code = _call_error_code(
        lambda: sesv2.put_configuration_set_sending_options(
            ConfigurationSetName=name, SendingEnabled=False
        )
    )
    assert mutate_code == missing, (
        f"PutConfigurationSetSendingOptions({name}) succeeded or returned {mutate_code!r} after "
        f"the configuration set was deleted; the same call succeeded while it existed, so the dead "
        f"name must now be unusable with NotFoundException"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
