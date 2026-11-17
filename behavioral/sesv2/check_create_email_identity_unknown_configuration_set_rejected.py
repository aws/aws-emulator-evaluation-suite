"""create-email-identity-unknown-configuration-set-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-email-identity-unknown-configuration-set-rejected"
GROUP = "identity-v2"
SERVICES = ["sesv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateEmailIdentity naming a configuration set that does not exist is refused
    NotFoundException, and the identity is never created.
    """
    ses = ctx.client("sesv2")

    missing_set = ctx.unique_name("sim2real-behav-v2idcs-missing-")
    identity = ctx.unique_name("sim2real-behav-v2idcsgone-") + "@example.com"

    code, msg = _error(
        lambda: ses.create_email_identity(
            EmailIdentity=identity, ConfigurationSetName=missing_set
        )
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code!r}"
    expected_msg = f"Configuration set <{missing_set}> does not exist."
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    read_code, read_msg = _error(lambda: ses.get_email_identity(EmailIdentity=identity))
    assert read_code == "NotFoundException", f"expected NotFoundException, got {read_code!r}"
    expected_read_msg = f"Email identity <{identity}> does not exist."
    assert read_msg == expected_read_msg, f"expected message {expected_read_msg!r}, got {read_msg!r}"

    # Positive control: the identical call against a configuration set that exists succeeds,
    # and the association is visible via an independent read.
    real_set = ctx.unique_name("sim2real-behav-v2idcs-real-")
    ses.create_configuration_set(ConfigurationSetName=real_set)
    ctx.on_cleanup(lambda _k=real_set: ses.delete_configuration_set(ConfigurationSetName=_k))

    ses.create_email_identity(EmailIdentity=identity, ConfigurationSetName=real_set)
    ctx.on_cleanup(lambda _k=identity: ses.delete_email_identity(EmailIdentity=_k))

    got = ses.get_email_identity(EmailIdentity=identity)
    assert got.get("ConfigurationSetName") == real_set, (
        f"expected {real_set!r}, got {got.get('ConfigurationSetName')!r}"
    )


def _error(fn):
    """Call fn(); return its (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
