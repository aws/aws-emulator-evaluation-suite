"""primary-tax-registration-full-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "primary-tax-registration-full-lifecycle"
GROUP = "state"
SERVICES = ["taxsettings"]

_NOT_FOUND = "No tax registration found"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:taxsettings-primary-registration")
def run(ctx) -> None:
    """The primary tax registration goes through Put, a second Put (ConflictException while the first is pending,
    else a replacement), Delete, a refused and a valid BatchPutTaxRegistration and a BatchDeleteTaxRegistration,
    each read back by GetTaxRegistration with the exact status, registrationId or not-found message."""
    ts = ctx.client("taxsettings")

    if _registration_exists(ts):
        raise AssertionError(
            "account already has a primary TaxRegistration configured; skipping "
            "rather than mutate/replace a real tax configuration this check does "
            "not own"
        )

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    ctx.on_cleanup(lambda: _delete_tolerating_not_found(ts))

    entry_de = _germany_entry("DE123456789", "Sim2Real Behavioral Test GmbH")
    put_resp = ts.put_tax_registration(taxRegistrationEntry=entry_de)
    status_after_put = put_resp["status"]
    assert status_after_put != "Deleted", (
        f"Put should never itself report the just-created TRN as Deleted, got {status_after_put!r}"
    )

    # The Put response reflects the status at submission time; a follow-up Get
    # may already show a further-advanced status if verification completed
    # fast (e.g. DE resolves quickly) -- both are valid non-terminal-or-verified
    # states, so assert membership in the known status set rather than exact
    # equality to the split-second-earlier Put response.
    get_resp = ts.get_tax_registration()["taxRegistration"]
    assert get_resp["status"] in {"Verified", "Pending", "Rejected"}, get_resp["status"]
    assert get_resp["registrationId"] == "DE123456789", (
        f"expected the just-Put DE123456789 on independent Get, got {get_resp['registrationId']!r}"
    )

    # Break/overwrite: a second Put for a different jurisdiction is only
    # blocked with ConflictException while the first TRN is still Pending
    # (per the documented "can't set a TRN if there's a pending TRN"
    # constraint) -- if the first already resolved to Verified before this
    # runs, the second Put is allowed to replace it. Either way the account's
    # primary TRN must remain a well-formed singleton: exactly one of the two
    # registrationIds is current, never both, never neither.
    entry_de2 = _germany_entry("DE987654321", "Sim2Real Conflicting GmbH")
    try:
        ts.put_tax_registration(taxRegistrationEntry=entry_de2)
        code = None
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "ConflictException", f"unexpected code for second Put: {code!r}"
        expected = "There is a pending TRN for the account. Please delete that first and retry the request."
        message = exc.response["Error"].get("Message")
        assert message == expected, f"expected conflict message {expected!r}, got {message!r}"
    get_after_second = ts.get_tax_registration()["taxRegistration"]
    if code == "ConflictException":
        assert get_after_second["registrationId"] == "DE123456789", (
            "second Put was rejected as a conflict, so the primary TRN must still be "
            f"the first one (DE123456789); got {get_after_second['registrationId']!r}"
        )
    else:
        assert get_after_second["registrationId"] == "DE987654321", (
            "second Put was accepted (first TRN had already resolved), so the primary "
            f"TRN must now be the second one (DE987654321); got {get_after_second['registrationId']!r}"
        )

    ts.delete_tax_registration()
    code_after_delete, message_after_delete = _error(lambda: ts.get_tax_registration())
    assert code_after_delete == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after delete, got {code_after_delete!r}"
    )
    assert message_after_delete == _NOT_FOUND, f"expected {_NOT_FOUND!r}, got {message_after_delete!r}"

    # A BatchPut whose entry fails a country business rule must create nothing.
    entry_ke_invalid = _kenya_entry(with_person_type=False)
    code2, message2 = _error(
        lambda: ts.batch_put_tax_registration(
            accountIds=[account_id], taxRegistrationEntry=entry_ke_invalid
        )
    )
    assert code2 == "ValidationException", f"expected ValidationException for invalid KE entry, got {code2!r}"
    expected2 = (
        "Your request has an AdditionalInfo object that isn't valid or is missing information. "
        "Check your request and try again."
    )
    assert message2 == expected2, f"expected message {expected2!r}, got {message2!r}"
    code_after_bad_batch, message_after_bad_batch = _error(lambda: ts.get_tax_registration())
    assert code_after_bad_batch == "ResourceNotFoundException", (
        "a BatchPut rejected for a business-rule violation must create nothing, but an "
        f"independent Get returned {code_after_bad_batch!r} instead of ResourceNotFoundException"
    )
    assert message_after_bad_batch == _NOT_FOUND, (
        f"expected {_NOT_FOUND!r}, got {message_after_bad_batch!r}"
    )

    # A valid BatchPut succeeds for the caller account (a country with no
    # additionalTaxInformation requirement, to isolate this from Kenya's
    # separate business-rule requirement tested above).
    entry_de3 = _germany_entry("DE555555555", "Sim2Real Batch GmbH")
    batch_put_resp = ts.batch_put_tax_registration(
        accountIds=[account_id], taxRegistrationEntry=entry_de3
    )
    assert batch_put_resp["errors"] == [], (
        f"expected BatchPut to succeed for the caller account, got errors={batch_put_resp['errors']!r}"
    )
    # BatchPut answers at submission time, before verification resolves, so its own
    # status is Pending; the independent Get is polled to the terminal verification
    # outcome, which for this fabricated VAT number is Rejected.
    assert batch_put_resp["status"] == "Pending", (
        f"expected BatchPut to answer with the submission-time status Pending, got {batch_put_resp['status']!r}"
    )
    get_after_batch = _poll_terminal(ts)
    assert get_after_batch["status"] == "Rejected", (
        "the fabricated DE VAT number must resolve to Rejected on independent Get, "
        f"got {get_after_batch['status']!r} (BatchPut said {batch_put_resp['status']!r})"
    )
    assert get_after_batch["registrationId"] == entry_de3["registrationId"], (
        f"expected the BatchPut-created {entry_de3['registrationId']!r} on independent Get, "
        f"got {get_after_batch['registrationId']!r}"
    )

    # BatchDelete removes it for the caller account.
    batch_del_resp = ts.batch_delete_tax_registration(accountIds=[account_id])
    assert batch_del_resp["errors"] == [], (
        f"expected BatchDelete to succeed for the caller account, got errors={batch_del_resp['errors']!r}"
    )
    code_after_batch_delete, message_after_batch_delete = _error(lambda: ts.get_tax_registration())
    assert code_after_batch_delete == "ResourceNotFoundException", (
        "independent Get after BatchDelete must report the TRN gone, got "
        f"{code_after_batch_delete!r} instead of ResourceNotFoundException"
    )
    assert message_after_batch_delete == _NOT_FOUND, (
        f"expected {_NOT_FOUND!r}, got {message_after_batch_delete!r}"
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


def _poll_terminal(ts, timeout_s: float = 180.0, interval_s: float = 5.0) -> dict:
    """Polls GetTaxRegistration until verification leaves Pending; raises on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        registration = ts.get_tax_registration()["taxRegistration"]
        if registration["status"] != "Pending":
            return registration
        if time.monotonic() >= deadline:
            raise AssertionError(f"tax registration still Pending after {timeout_s}s: {registration!r}")
        time.sleep(interval_s)


def _registration_exists(ts) -> bool:
    try:
        ts.get_tax_registration()
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return False
        raise
    return True


def _delete_tolerating_not_found(ts) -> None:
    try:
        ts.delete_tax_registration()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _germany_entry(registration_id: str, legal_name: str) -> dict:
    return {
        "registrationId": registration_id,
        "registrationType": "VAT",
        "legalName": legal_name,
        "legalAddress": {
            "addressLine1": "Teststrasse 1",
            "city": "Berlin",
            "postalCode": "10115",
            "countryCode": "DE",
        },
    }


def _kenya_entry(with_person_type: bool) -> dict:
    entry = {
        "registrationId": "P123456789K",
        "registrationType": "VAT",
        "legalName": "Sim2Real Kenya Test Ltd",
        "legalAddress": {
            "addressLine1": "Kenyatta Ave 1",
            "city": "Nairobi",
            "postalCode": "00100",
            "countryCode": "KE",
        },
    }
    if with_person_type:
        entry["additionalTaxInformation"] = {"kenyaAdditionalInfo": {"personType": "Business"}}
    return entry


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
