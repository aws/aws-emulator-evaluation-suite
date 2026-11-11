"""put-alternate-contact-invalid-email-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-alternate-contact-invalid-email-rejected"
GROUP = "overly-permissive"
SERVICES = ["account"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:account-contacts")
def run(ctx) -> None:
    """PutAlternateContact with a malformed EmailAddress is rejected with ValidationException,
    the existing contact is left untouched, and a valid Put still succeeds (positive control)."""
    account = ctx.client("account")
    contact_type = "SECURITY"

    original = _get_alt_contact(ctx, contact_type)
    ctx.on_cleanup(lambda: _restore_alt_contact(ctx, contact_type, original))

    # seed a known-good baseline so we can prove it survives the rejected call
    account.put_alternate_contact(
        AlternateContactType=contact_type,
        Name="Sim2Real Baseline Contact",
        Title="Baseline",
        EmailAddress="sim2real-behav-baseline@example.com",
        PhoneNumber="+1 555 0155",
    )

    code, message = _error_code(
        lambda: account.put_alternate_contact(
            AlternateContactType=contact_type,
            Name="Sim2Real Bad Email Contact",
            Title="Bad",
            EmailAddress="not-a-valid-email-address",  # missing '@' -- violates the EmailAddress pattern
            PhoneNumber="+1 555 0166",
        )
    )
    assert code == "ValidationException", f"expected ValidationException for malformed EmailAddress, got {code!r}"
    assert message == (
        r'[ECMA 262 regex "^[\s]*[\w+=.#|!&-]+@[\w.-]+\.[\w]+[\s]*$" '
        'does not match input string "not-a-valid-email-address"]'
    ), message

    # the effect must be absent: baseline is unchanged
    fetched = account.get_alternate_contact(AlternateContactType=contact_type)["AlternateContact"]
    assert fetched["Name"] == "Sim2Real Baseline Contact", (
        f"expected baseline Name to survive the rejected Put, got {fetched['Name']!r}"
    )
    assert fetched["EmailAddress"] == "sim2real-behav-baseline@example.com", (
        f"expected baseline EmailAddress to survive the rejected Put, got {fetched['EmailAddress']!r}"
    )

    # positive control: a well-formed Put still succeeds
    account.put_alternate_contact(
        AlternateContactType=contact_type,
        Name="Sim2Real Good Email Contact",
        Title="Good",
        EmailAddress="sim2real-behav-good@example.com",
        PhoneNumber="+1 555 0177",
    )
    fetched2 = account.get_alternate_contact(AlternateContactType=contact_type)["AlternateContact"]
    assert fetched2["Name"] == "Sim2Real Good Email Contact", (
        f"expected the well-formed Put to persist, got Name={fetched2['Name']!r}"
    )


def _error_code(fn):
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
