"""create-relationship-invalid-sector-enum-validation-order."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-relationship-invalid-sector-enum-validation-order"
GROUP = "error-semantics"
SERVICES = ["partnercentral-channel"]

CATALOG = "Sandbox"
BENEFIT_DENIED = (
    "This action requires an active AWS Partner benefit. Register as an AWS Partner "
    "if you haven't already, or contact AWS Partner Central Support."
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateRelationship on a nonexistent PMA is refused with the exact entitlement
    AccessDeniedException, while an out-of-enum `sector` gets ValidationException with the exact message
    and fieldList: shape validation runs before the entitlement gate."""
    client = ctx.client("partnercentral-channel")
    fake_pma_id = "pma-1111111111111"

    def _attempt(sector):
        return client.create_relationship(
            catalog=CATALOG,
            associationType="END_CUSTOMER",
            programManagementAccountIdentifier=fake_pma_id,
            associatedAccountId="".join(["1"] * 12),
            displayName=ctx.unique_name("sim2real-rel-")[:30],
            sector=sector,
        )

    valid = _error(lambda: _attempt("COMMERCIAL"))
    code_valid = valid["Error"]["Code"]
    assert code_valid == "AccessDeniedException", (
        f"well-formed sector against nonexistent PMA: expected AccessDeniedException, got {code_valid}"
    )
    assert valid["Error"].get("Message") == BENEFIT_DENIED, valid

    invalid = _error(lambda: _attempt("NOT_A_REAL_SECTOR_VALUE"))
    code_invalid = invalid["Error"]["Code"]
    assert code_invalid == "ValidationException", (
        f"out-of-enum sector: expected ValidationException, got {code_invalid}"
    )
    assert invalid["Error"].get("Message") == "1 validation error detected.", invalid
    assert invalid.get("fieldList") == [
        {
            "name": "sector",
            "code": "INVALID_ENUM_VALUE",
            "message": "Value at 'sector' failed to satisfy constraint: Member must satisfy "
            "enum value set: [GOVERNMENT_EXCEPTION, COMMERCIAL, GOVERNMENT]",
        }
    ], f"fieldList={invalid.get('fieldList')!r}"


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
