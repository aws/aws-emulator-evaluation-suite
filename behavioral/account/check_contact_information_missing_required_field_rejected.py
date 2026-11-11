"""contact-information-missing-required-field-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "contact-information-missing-required-field-rejected"
GROUP = "overly-permissive"
SERVICES = ["account"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:account-contacts")
def run(ctx) -> None:
    """PutContactInformation without the required PostalCode, sent past client-side validation, is
    rejected by the service with ValidationException; the stored contact information is unchanged
    and a complete Put still succeeds."""
    account = ctx.client("account")

    original = account.get_contact_information()["ContactInformation"]
    ctx.on_cleanup(lambda: _restore_contact_information(account, original))

    baseline = {
        "FullName": "Sim2Real Baseline Person",
        "AddressLine1": "1 Baseline Street",
        "City": "Seattle",
        "StateOrRegion": "WA",
        "PostalCode": "98101",
        "CountryCode": "US",
        "PhoneNumber": "+1 206 555 0111",
    }
    account.put_contact_information(ContactInformation=baseline)

    incomplete = dict(baseline)
    incomplete["FullName"] = "Sim2Real Incomplete Person"
    del incomplete["PostalCode"]  # required field omitted

    unvalidated_account = ctx.client("account", config=Config(parameter_validation=False))
    code, message = _error_code(lambda: unvalidated_account.put_contact_information(ContactInformation=incomplete))
    assert code == "ValidationException", f"expected a server-side ValidationException for missing PostalCode, got {code!r}"
    assert message == '[object has missing required properties (["PostalCode"])]', message

    # the effect must be absent: the baseline (not the rejected attempt) is what's on file
    fetched = account.get_contact_information()["ContactInformation"]
    assert fetched["FullName"] == "Sim2Real Baseline Person", (
        f"expected baseline FullName to survive the rejected Put, got {fetched.get('FullName')!r}"
    )
    assert fetched["PostalCode"] == "98101", (
        f"expected baseline PostalCode to survive the rejected Put, got {fetched.get('PostalCode')!r}"
    )

    # positive control: a complete Put still succeeds
    account.put_contact_information(ContactInformation={**baseline, "FullName": "Sim2Real Complete Person"})
    fetched2 = account.get_contact_information()["ContactInformation"]
    assert fetched2["FullName"] == "Sim2Real Complete Person", (
        f"expected complete Put to succeed, got FullName={fetched2.get('FullName')!r}"
    )


def _error_code(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises, so a target
    accepting what AWS refuses cannot be read as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _restore_contact_information(account, original: dict) -> None:
    """Teardown: put the account's prior contact information back. PutContactInformation refuses a
    stored phone number that lacks the leading '+' its pattern requires, so that one value gets the
    country prefix the pattern asks for."""
    phone = original.get("PhoneNumber", "")
    if phone and not phone.startswith("+"):
        prefix = "+1 " if original.get("CountryCode") == "US" else "+"
        original = {**original, "PhoneNumber": prefix + phone}
    account.put_contact_information(ContactInformation=original)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
