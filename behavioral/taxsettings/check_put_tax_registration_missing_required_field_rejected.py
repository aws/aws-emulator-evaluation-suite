"""put-tax-registration-missing-required-field-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-tax-registration-missing-required-field-rejected"
GROUP = "error-semantics"
SERVICES = ["taxsettings"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:taxsettings-primary-registration")
def run(ctx) -> None:
    """PutTaxRegistration for Kenya without kenyaAdditionalInfo.personType is refused with ValidationException and
    its exact message, and GetTaxRegistration still answers ResourceNotFoundException."""
    ts = ctx.client("taxsettings")

    if _registration_exists(ts):
        raise AssertionError(
            "a primary TaxRegistration currently exists on this account; skipping "
            "to avoid an ambiguous ConflictException-vs-ValidationException race "
            "with whichever check owns it"
        )

    entry = {
        "registrationId": "P987654321K",
        "registrationType": "VAT",
        "legalName": "Sim2Real Kenya Missing Field Ltd",
        "legalAddress": {
            "addressLine1": "Kenyatta Ave 2",
            "city": "Nairobi",
            "postalCode": "00100",
            "countryCode": "KE",
        },
        # deliberately no additionalTaxInformation.kenyaAdditionalInfo.personType
    }

    code, message = _error(lambda: ts.put_tax_registration(taxRegistrationEntry=entry))
    assert code == "ValidationException", (
        f"expected ValidationException for a Kenyan TRN missing "
        f"additionalTaxInformation.kenyaAdditionalInfo.personType, got {code!r}"
    )
    expected = (
        "Your request has an AdditionalInfo object that isn't valid or is missing information. "
        "Check your request and try again."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: still no primary TRN on the account.
    code_after, message_after = _error(lambda: ts.get_tax_registration())
    assert code_after == "ResourceNotFoundException", (
        f"a rejected PutTaxRegistration must not create a primary TRN, "
        f"but get_tax_registration() returned {code_after!r} instead of ResourceNotFoundException"
    )
    assert message_after == "No tax registration found", (
        f"expected 'No tax registration found', got {message_after!r}"
    )


def _error(fn):
    """The rejected call's (code, message); an unexpected success raises, so an emulator that
    accepts what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _registration_exists(ts) -> bool:
    try:
        ts.get_tax_registration()
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return False
        raise
    return True


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
