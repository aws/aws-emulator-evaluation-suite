"""alternate-contact-overwrite-replaces-previous-value."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "alternate-contact-overwrite-replaces-previous-value"
GROUP = "state"
SERVICES = ["account"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:account-contacts")
def run(ctx) -> None:
    """A second PutAlternateContact call for the same type fully replaces the first (no merge)."""
    account = ctx.client("account")
    contact_type = "OPERATIONS"

    original = _get_alt_contact(ctx, contact_type)
    ctx.on_cleanup(lambda: _restore_alt_contact(ctx, contact_type, original))

    account.put_alternate_contact(
        AlternateContactType=contact_type,
        Name="Sim2Real First Contact",
        Title="Original Title",
        EmailAddress="sim2real-behav-ops-v1@example.com",
        PhoneNumber="+1 555 0111",
    )
    account.put_alternate_contact(
        AlternateContactType=contact_type,
        Name="Sim2Real Second Contact",
        Title="Replacement Title",
        EmailAddress="sim2real-behav-ops-v2@example.com",
        PhoneNumber="+1 555 0122",
    )

    fetched = account.get_alternate_contact(AlternateContactType=contact_type)["AlternateContact"]
    assert fetched["Name"] == "Sim2Real Second Contact", (
        f"expected Name 'Sim2Real Second Contact', got {fetched['Name']!r}"
    )
    assert fetched["Title"] == "Replacement Title", (
        f"expected Title 'Replacement Title', got {fetched['Title']!r}"
    )
    assert fetched["EmailAddress"] == "sim2real-behav-ops-v2@example.com", (
        f"expected EmailAddress 'sim2real-behav-ops-v2@example.com', got {fetched['EmailAddress']!r}"
    )
    assert fetched["PhoneNumber"] == "+1 555 0122", (
        f"expected PhoneNumber '+1 555 0122', got {fetched['PhoneNumber']!r}"
    )
    # the first value must be fully gone, not merged in
    assert fetched["Name"] != "Sim2Real First Contact", (
        f"first contact's Name leaked through overwrite: still reads back as {fetched['Name']!r}"
    )


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
