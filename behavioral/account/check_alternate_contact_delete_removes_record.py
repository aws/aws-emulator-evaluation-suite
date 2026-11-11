"""alternate-contact-delete-removes-record."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "alternate-contact-delete-removes-record"
GROUP = "state"
SERVICES = ["account"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:account-contacts")
def run(ctx) -> None:
    """DeleteAlternateContact removes the record so a subsequent Get raises ResourceNotFoundException."""
    account = ctx.client("account")
    contact_type = "BILLING"

    original = _get_alt_contact(ctx, contact_type)
    ctx.on_cleanup(lambda: _restore_alt_contact(ctx, contact_type, original))

    account.put_alternate_contact(
        AlternateContactType=contact_type,
        Name="Sim2Real Billing Contact",
        Title="Finance",
        EmailAddress="sim2real-behav-billing@example.com",
        PhoneNumber="+1 555 0133",
    )
    # confirm it is really there before deleting
    before = account.get_alternate_contact(AlternateContactType=contact_type)["AlternateContact"]["Name"]
    assert before == "Sim2Real Billing Contact", f"expected the seeded contact to be readable, got {before!r}"

    account.delete_alternate_contact(AlternateContactType=contact_type)

    code, message = _error_code(lambda: account.get_alternate_contact(AlternateContactType=contact_type))
    assert code == "ResourceNotFoundException", (
        f"expected Get after Delete to raise ResourceNotFoundException, got {code!r}"
    )
    assert message == "No contact of the inputted alternate contact type found.", message

    # a mutation on the now-dead record must also fail, not silently no-op
    second_delete_code, second_delete_message = _error_code(
        lambda: account.delete_alternate_contact(AlternateContactType=contact_type)
    )
    assert second_delete_code == "ResourceNotFoundException", (
        f"expected a second Delete on an already-deleted contact to raise ResourceNotFoundException, "
        f"got {second_delete_code!r}"
    )
    assert second_delete_message == "No contact of the inputted alternate contact type found.", second_delete_message

    # the identifier is reusable: a fresh Put on the same type succeeds and is what Get now returns
    account.put_alternate_contact(
        AlternateContactType=contact_type,
        Name="Sim2Real Billing Contact Reused",
        Title="Finance",
        EmailAddress="sim2real-behav-billing-reused@example.com",
        PhoneNumber="+1 555 0177",
    )
    reused = account.get_alternate_contact(AlternateContactType=contact_type)["AlternateContact"]["Name"]
    assert reused == "Sim2Real Billing Contact Reused", (
        f"expected the contact type to be reusable after delete, got {reused!r}"
    )


def _error_code(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises, so a target
    accepting what AWS refuses cannot be read as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _get_alt_contact(ctx, contact_type: str):
    account = ctx.client("account")
    try:
        return account.get_alternate_contact(AlternateContactType=contact_type)["AlternateContact"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _restore_alt_contact(ctx, contact_type: str, original) -> None:
    account = ctx.client("account")
    if original is None:
        try:
            account.delete_alternate_contact(AlternateContactType=contact_type)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
    else:
        account.put_alternate_contact(
            AlternateContactType=contact_type,
            Name=original["Name"],
            Title=original["Title"],
            EmailAddress=original["EmailAddress"],
            PhoneNumber=original["PhoneNumber"],
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
