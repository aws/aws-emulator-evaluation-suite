"""update-program-management-account-nonexistent-error."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-program-management-account-nonexistent-error"
GROUP = "overly-permissive"
SERVICES = ["partnercentral-channel"]

CATALOG = "Sandbox"
BENEFIT_DENIED = (
    "This action requires an active AWS Partner benefit. Register as an AWS Partner "
    "if you haven't already, or contact AWS Partner Central Support."
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateProgramManagementAccount rejects a malformed identifier with ValidationException (exact
    message and fieldList), while a well-formed nonexistent identifier gets the exact entitlement
    AccessDeniedException for a caller without an active AWS Partner benefit."""
    client = ctx.client("partnercentral-channel")
    fake_pma_id = "pma-1111111111111"
    malformed_id = "not-a-pma-identifier"

    def _attempt(identifier):
        client.update_program_management_account(
            catalog=CATALOG,
            identifier=identifier,
            revision="1",
            displayName=ctx.unique_name("sim2real-pma-upd-")[:30],
        )

    malformed = _error(lambda: _attempt(malformed_id))
    code_malformed = malformed["Error"]["Code"]
    assert code_malformed == "ValidationException", (
        f"malformed identifier {malformed_id!r}: expected ValidationException, got {code_malformed}"
    )
    assert malformed["Error"].get("Message") == "1 validation error detected.", malformed
    assert malformed.get("fieldList") == [
        {
            "name": "identifier",
            "code": "INVALID_STRING_FORMAT",
            "message": "Value at 'identifier' failed to satisfy constraint: Member must "
            "satisfy regular expression pattern: either a resource ID starting with pma- "
            "followed by 13 alphanumeric characters or a full ARN",
        }
    ], f"fieldList={malformed.get('fieldList')!r}"

    denied = _error(lambda: _attempt(fake_pma_id))
    code = denied["Error"]["Code"]
    assert code == "AccessDeniedException", (
        f"well-formed but nonexistent identifier {fake_pma_id!r}: "
        f"expected AccessDeniedException, got {code}"
    )
    assert denied["Error"].get("Message") == BENEFIT_DENIED, denied


def _error(fn):
    """Call fn(); return its botocore response dict (Code/Message under "Error", modeled
    error members such as fieldList at the top level). An unexpected SUCCESS raises, so a
    target that accepts input real AWS refuses cannot pass as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
