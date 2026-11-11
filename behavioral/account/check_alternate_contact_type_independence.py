"""alternate-contact-type-independence."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "alternate-contact-type-independence"
GROUP = "state"
SERVICES = ["account"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:account-contacts")
def run(ctx) -> None:
    """BILLING and SECURITY alternate contacts are stored independently: writing one does not
    affect or leak into the other."""
    account = ctx.client("account")

    original_billing = _get_alt_contact(ctx, "BILLING")
    original_security = _get_alt_contact(ctx, "SECURITY")
    ctx.on_cleanup(lambda: _restore_alt_contact(ctx, "BILLING", original_billing))
    ctx.on_cleanup(lambda: _restore_alt_contact(ctx, "SECURITY", original_security))

    account.put_alternate_contact(
        AlternateContactType="BILLING",
        Name="Sim2Real Billing Person",
        Title="Billing Lead",
        EmailAddress="sim2real-behav-billing-iso@example.com",
        PhoneNumber="+1 555 0188",
    )
    account.put_alternate_contact(
        AlternateContactType="SECURITY",
        Name="Sim2Real Security Person",
        Title="Security Lead",
        EmailAddress="sim2real-behav-security-iso@example.com",
        PhoneNumber="+1 555 0199",
    )

    billing = account.get_alternate_contact(AlternateContactType="BILLING")["AlternateContact"]
    security = account.get_alternate_contact(AlternateContactType="SECURITY")["AlternateContact"]

    assert billing["Name"] == "Sim2Real Billing Person", (
        f"BILLING contact leaked/overwritten: expected 'Sim2Real Billing Person', got {billing['Name']!r}"
    )
    assert billing["AlternateContactType"] == "BILLING", (
        f"expected AlternateContactType 'BILLING', got {billing['AlternateContactType']!r}"
    )
    assert security["Name"] == "Sim2Real Security Person", (
        f"SECURITY contact leaked/overwritten: expected 'Sim2Real Security Person', got {security['Name']!r}"
    )
    assert security["AlternateContactType"] == "SECURITY", (
        f"expected AlternateContactType 'SECURITY', got {security['AlternateContactType']!r}"
    )
    assert billing["EmailAddress"] != security["EmailAddress"], (
        "BILLING and SECURITY contacts must not share an email address after independent writes: "
        f"both read back as {billing['EmailAddress']!r}"
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
