"""supplemental-tax-registration-unsupported-country-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "supplemental-tax-registration-unsupported-country-rejected"
GROUP = "overly-permissive"
SERVICES = ["taxsettings"]

_UNSUPPORTED = "Tax registration for country is not supported."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutSupplementalTaxRegistration refuses FR and a second unsupported country with ValidationException and the
    exact message and creates neither, while CH, a supported country, is not refused with ValidationException."""
    ts = ctx.client("taxsettings")

    supported = _supplemental_entry("CH", "CHE123456789MWST", "Sim2Real CH Supported AG",
                                      "Teststrasse 1", "Zurich", "8001")
    try:
        ts.put_supplemental_tax_registration(taxRegistrationEntry=supported)
        supported_code = None
    except ClientError as exc:
        supported_code = exc.response["Error"]["Code"]
    assert supported_code != "ValidationException", (
        f"CH is a supported supplemental-TRN country and must clear country validation, "
        f"got ValidationException (code={supported_code!r}) -- indistinguishable from a target "
        f"that rejects every PutSupplementalTaxRegistration call"
    )
    if supported_code is None:
        ctx.on_cleanup(lambda: ts.delete_supplemental_tax_registration(authorityId=supported["registrationId"]))
        listed_supported = _list_all_supplemental(ts)
        assert any(r["registrationId"] == supported["registrationId"] for r in listed_supported), (
            "accepted CH entry must appear in an independent list read"
        )

    unsupported = _supplemental_entry("FR", "FR12345678901", "Sim2Real FR Unsupported SARL",
                                       "1 Rue de Test", "Testville", "75000")
    code, message = _error(lambda: ts.put_supplemental_tax_registration(taxRegistrationEntry=unsupported))
    assert code == "ValidationException", (
        f"expected ValidationException for an unsupported supplemental-TRN country, got {code!r}"
    )
    assert message == _UNSUPPORTED, f"expected {_UNSUPPORTED!r}, got {message!r}"
    listed = _list_all_supplemental(ts)
    assert all(r["registrationId"] != unsupported["registrationId"] for r in listed), (
        "rejected FR entry must not have been created"
    )

    # A second, differently-shaped unsupported country hits the same
    # boundary, confirming the rejection is a general country-support check
    # rather than a quirk of one specific country/address shape.
    unsupported2 = _supplemental_entry("GB", "GB123456789", "Sim2Real GB Unsupported Ltd",
                                        "1 Test Street", "London", "SW1A 1AA")
    code2, message2 = _error(lambda: ts.put_supplemental_tax_registration(taxRegistrationEntry=unsupported2))
    assert code2 == "ValidationException", (
        f"expected ValidationException for a second unsupported country, got {code2!r}"
    )
    assert message2 == _UNSUPPORTED, f"expected {_UNSUPPORTED!r}, got {message2!r}"
    listed2 = _list_all_supplemental(ts)
    assert all(r["registrationId"] != unsupported2["registrationId"] for r in listed2)


def _error(fn):
    """The rejected call's (code, message); an unexpected success raises, so an emulator that
    accepts what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _supplemental_entry(
    country_code: str, registration_id: str, legal_name: str,
    address_line1: str, city: str, postal_code: str,
) -> dict:
    return {
        "registrationId": registration_id,
        "registrationType": "VAT",
        "legalName": legal_name,
        "address": {
            "addressLine1": address_line1,
            "city": city,
            "postalCode": postal_code,
            "countryCode": country_code,
        },
    }


def _list_all_supplemental(ts) -> list:
    out = []
    kwargs: dict = {}
    while True:
        resp = ts.list_supplemental_tax_registrations(**kwargs)
        out.extend(resp.get("taxRegistrations", []))
        token = resp.get("nextToken")
        if not token:
            return out
        kwargs = {"nextToken": token}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


