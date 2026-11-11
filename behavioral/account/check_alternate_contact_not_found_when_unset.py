"""alternate-contact-not-found-when-unset."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "alternate-contact-not-found-when-unset"
GROUP = "overly-permissive"
SERVICES = ["account"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:account-contacts")
def run(ctx) -> None:
    """Get/Delete on an alternate contact type that has never been set raise ResourceNotFoundException,
    while Put+Get for that same type still succeeds (in-file positive control)."""
    account = ctx.client("account")
    contact_type = "OPERATIONS"

    original = _get_alt_contact(ctx, contact_type)
    ctx.on_cleanup(lambda: _restore_alt_contact(ctx, contact_type, original))
    # force the type to be unset for this test regardless of prior state
    if original is not None:
        account.delete_alternate_contact(AlternateContactType=contact_type)

    get_code, get_message = _error_code(
        lambda: account.get_alternate_contact(AlternateContactType=contact_type), "GetAlternateContact"
    )
    assert get_code == "ResourceNotFoundException", (
        f"expected GetAlternateContact on unset {contact_type} to raise ResourceNotFoundException, "
        f"got code={get_code!r}"
    )
    assert get_message == "No contact of the inputted alternate contact type found.", get_message

    delete_code, delete_message = _error_code(
        lambda: account.delete_alternate_contact(AlternateContactType=contact_type), "DeleteAlternateContact"
    )
    assert delete_code == "ResourceNotFoundException", (
        f"expected DeleteAlternateContact on unset {contact_type} to raise ResourceNotFoundException, "
        f"got code={delete_code!r}"
    )
    assert delete_message == "No contact of the inputted alternate contact type found.", delete_message

    # positive control: the same operations succeed once the contact actually exists
    account.put_alternate_contact(
        AlternateContactType=contact_type,
        Name="Sim2Real Control Contact",
        Title="Control",
        EmailAddress="sim2real-behav-control@example.com",
        PhoneNumber="+1 555 0144",
    )
    fetched = account.get_alternate_contact(AlternateContactType=contact_type)["AlternateContact"]
    assert fetched["Name"] == "Sim2Real Control Contact", (
        f"positive control: expected round-tripped Name 'Sim2Real Control Contact', got {fetched['Name']!r}"
    )


def _error_code(fn, description: str):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected {description} to fail on the unset contact type, but it succeeded and returned {result!r}")


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
