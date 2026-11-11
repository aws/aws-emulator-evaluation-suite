"""batch-put-tax-registration-empty-accountids-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-put-tax-registration-empty-accountids-rejected"
GROUP = "error-semantics"
SERVICES = ["taxsettings"]

_CONTROL_MESSAGE = (
    "Your request has an AdditionalInfo object that isn't valid or is missing information. "
    "Check your request and try again."
)
_EMPTY_LIST_MESSAGE = (
    "1 validation error detected: Value at 'accountIds' failed to satisfy constraint: "
    "Member must have length greater than or equal to 1"
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:taxsettings-primary-registration")
def run(ctx) -> None:
    """BatchPutTaxRegistration sent unvalidated with accountIds=[] is refused with ValidationException and the exact
    accountIds length message, distinct from the exact message refusing a Kenya entry on a business rule; neither
    call changes the account's primary TaxRegistration."""
    ts = ctx.client("taxsettings")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    entry = {
        "registrationId": "DE111111111",
        "registrationType": "VAT",
        "legalName": "Sim2Real Empty List Test GmbH",
        "sector": "Business",
        "legalAddress": {
            "addressLine1": "Teststrasse 2",
            "city": "Berlin",
            "postalCode": "10115",
            "countryCode": "DE",
        },
    }

    # Kenya requires additionalTaxInformation.kenyaAdditionalInfo.personType; omitting
    # it is a business-rule violation on the ENTRY, refused before anything is stored.
    kenya_missing_person_type = {
        "registrationId": "P123456789K",
        "registrationType": "VAT",
        "legalName": "Sim2Real Empty List Control Ltd",
        "legalAddress": {
            "addressLine1": "Kenyatta Ave 1",
            "city": "Nairobi",
            "postalCode": "00100",
            "countryCode": "KE",
        },
    }

    before = _get_registration_state(ts)

    # --- Positive control: the operation reaches the service and is refused
    # for a reason that is NOT accountIds cardinality.
    ctrl_code, ctrl_msg = _err(
        lambda: ts.batch_put_tax_registration(
            accountIds=[account_id], taxRegistrationEntry=kenya_missing_person_type
        )
    )
    assert ctrl_code == "ValidationException", (
        f"expected the KE business-rule violation to reach the service as "
        f"ValidationException, got {ctrl_code!r}"
    )
    assert ctrl_msg == _CONTROL_MESSAGE, (
        "the business-rule control must be refused on the ENTRY, not on accountIds "
        f"cardinality; expected message {_CONTROL_MESSAGE!r}, got {ctrl_msg!r}"
    )
    assert _get_registration_state(ts) == before, (
        "the refused control BatchPut must not mutate the caller's primary TaxRegistration"
    )

    # --- Under test: accountIds=[] must reach the service unmangled (not
    raw = _unvalidated_client(ctx)
    code, msg = _err(
        lambda: raw.batch_put_tax_registration(accountIds=[], taxRegistrationEntry=entry)
    )
    assert code == "ValidationException", (
        f"expected ValidationException for an empty accountIds list, got {code!r}"
    )
    assert msg == _EMPTY_LIST_MESSAGE, (
        "the refusal of an empty accountIds list must name the member, distinguishing "
        f"it from the business-rule refusal above; expected {_EMPTY_LIST_MESSAGE!r}, got {msg!r}"
    )
    assert msg != ctrl_msg, (
        "the cardinality refusal and the business-rule refusal must carry distinct "
        f"messages, or the empty-list case is not actually being told apart from "
        f"'every BatchPut is refused'; both were {msg!r}"
    )
    assert _get_registration_state(ts) == before, (
        "the refused empty-accountIds BatchPut must not mutate the caller's primary "
        "TaxRegistration"
    )


def _err(fn):
    """Call fn(); return its error code and message. A SUCCESS raises: the call must be refused."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _get_registration_state(ts):
    try:
        return ts.get_tax_registration()["taxRegistration"]["registrationId"]
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")


def _unvalidated_client(ctx):
    """A taxsettings client with botocore's client-side parameter validation disabled.
    accountIds' minItems=1 lives in the model, so a validating client raises a local
    ParamValidationError and never sends accountIds=[] to the service."""
    return ctx.client(
        "taxsettings",
        config=Config(retries={"max_attempts": 1}, parameter_validation=False),
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
