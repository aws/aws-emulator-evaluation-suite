"""list-program-management-accounts-validation-precedes-access-denied."""
from __future__ import annotations


from behavioral_harness import tags

CHECK = "list-program-management-accounts-validation-precedes-access-denied"
GROUP = "error-semantics"
SERVICES = ["partnercentral-channel"]

CATALOG = "Sandbox"
BENEFIT_DENIED = (
    "This action requires an active AWS Partner benefit. Register as an AWS Partner "
    "if you haven't already, or contact AWS Partner Central Support."
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListProgramManagementAccounts rejects maxResults 101 with ValidationException (exact message and
    fieldList), while the same filter with a valid maxResults gets the exact entitlement
    AccessDeniedException: validation runs before authorization."""
    client = ctx.client("partnercentral-channel")
    account_id = _FOREIGN_ACCOUNT

    def _attempt_out_of_range():
        return client.list_program_management_accounts(
            catalog=CATALOG, accountIds=[account_id], maxResults=101
        )

    resp = _error(_attempt_out_of_range)
    error = resp["Error"]
    assert error["Code"] == "ValidationException", (
        f"expected ValidationException, got {error['Code']}"
    )
    assert error.get("Message") == "1 validation error detected.", error
    assert resp.get("fieldList") == [
        {
            "name": "maxResults",
            "code": "INVALID_VALUE",
            "message": "Value at 'maxResults' failed to satisfy constraint: "
            "Member must have value less than or equal to 100",
        }
    ], f"fieldList={resp.get('fieldList')!r}"

    def _attempt_in_range():
        return client.list_program_management_accounts(
            catalog=CATALOG, accountIds=[account_id], maxResults=100
        )

    resp2 = _error(_attempt_in_range)
    error2 = resp2["Error"]
    assert error2["Code"] == "AccessDeniedException", (
        f"expected AccessDeniedException, got {error2['Code']}"
    )
    assert error2.get("Message") == BENEFIT_DENIED, (
        f"expected the exact partner-benefit denial, got message={error2.get('Message')!r}"
    )


# A documentation placeholder account id: a made-up id could be a real account someone else owns.
_FOREIGN_ACCOUNT = "111122223333"


def _error(fn):
    """Call fn(); return its botocore response dict (Code/Message under "Error", modeled error
    members such as fieldList at the top level). An unexpected SUCCESS raises, because a target that
    accepts input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
