"""delete-program-management-account-nonexistent-error."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-program-management-account-nonexistent-error"
GROUP = "overly-permissive"
SERVICES = ["partnercentral-channel"]

CATALOG = "Sandbox"
_NO_PARTNER_BENEFIT = (
    "This action requires an active AWS Partner benefit. Register as an AWS Partner if you haven't "
    "already, or contact AWS Partner Central Support."
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteProgramManagementAccount rejects a malformed identifier with ValidationException and refuses a
    well-formed nonexistent one with the partner-benefit AccessDeniedException in an account without that
    benefit, else ResourceNotFoundException, with the same code and message on a second call."""
    client = ctx.client("partnercentral-channel")

    # Whether the account holds an active partner benefit decides which refusal a nonexistent
    # identifier gets, so read it from a separate call before grading the delete.
    try:
        client.list_program_management_accounts(catalog=CATALOG)
        partner = True
    except ClientError as exc:
        error = exc.response["Error"]
        assert (error["Code"], error.get("Message")) == ("AccessDeniedException", _NO_PARTNER_BENEFIT), error
        partner = False

    def _attempt_malformed():
        client.delete_program_management_account(
            catalog=CATALOG, identifier="not-a-valid-pma-identifier"
        )

    code0, _ = _error_code(_attempt_malformed)
    assert code0 == "ValidationException", f"expected ValidationException, got {code0}"

    fake_pma_id = "pma-1111111111111"

    def _attempt():
        client.delete_program_management_account(catalog=CATALOG, identifier=fake_pma_id)

    code1, msg1 = _error_code(_attempt)
    if partner:
        assert code1 == "ResourceNotFoundException", (code1, msg1)
    else:
        assert (code1, msg1) == ("AccessDeniedException", _NO_PARTNER_BENEFIT), (code1, msg1)

    code2, msg2 = _error_code(_attempt)
    assert code2 == code1 and msg2 == msg1, (code2, msg2, code1, msg1)


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
