"""alternate-contact-put-get-round-trip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "alternate-contact-put-get-round-trip"
GROUP = "state"
SERVICES = ["account"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:account-contacts")
def run(ctx) -> None:
    """PutAlternateContact fields are retrievable verbatim via GetAlternateContact."""
    account = ctx.client("account")
    contact_type = "SECURITY"

    original = _get_alt_contact(ctx, contact_type)
    ctx.on_cleanup(lambda: _restore_alt_contact(ctx, contact_type, original))

    account.put_alternate_contact(
        AlternateContactType=contact_type,
        Name="Sim2Real Behavioral Tester",
        Title="Automation Engineer",
        EmailAddress="sim2real-behav-security@example.com",
        PhoneNumber="+1 555 0100",
    )

    fetched = account.get_alternate_contact(AlternateContactType=contact_type)["AlternateContact"]
    assert fetched["Name"] == "Sim2Real Behavioral Tester", f"Name: expected 'Sim2Real Behavioral Tester', got {fetched['Name']!r}"
    assert fetched["Title"] == "Automation Engineer", f"Title: expected 'Automation Engineer', got {fetched['Title']!r}"
    assert fetched["EmailAddress"] == "sim2real-behav-security@example.com", (
        f"EmailAddress: expected 'sim2real-behav-security@example.com', got {fetched['EmailAddress']!r}"
    )
    assert fetched["PhoneNumber"] == "+1 555 0100", f"PhoneNumber: expected '+1 555 0100', got {fetched['PhoneNumber']!r}"
    assert fetched["AlternateContactType"] == contact_type, (
        f"AlternateContactType: expected {contact_type!r}, got {fetched['AlternateContactType']!r}"
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
