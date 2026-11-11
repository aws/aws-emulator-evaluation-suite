"""create-relationship-access-denied-for-nonexistent-pma."""
from __future__ import annotations


from behavioral_harness import tags

CHECK = "create-relationship-access-denied-for-nonexistent-pma"
GROUP = "overly-permissive"
SERVICES = ["partnercentral-channel"]

CATALOG = "Sandbox"
BENEFIT_DENIED = (
    "This action requires an active AWS Partner benefit. Register as an AWS Partner "
    "if you haven't already, or contact AWS Partner Central Support."
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateRelationship on a well-formed nonexistent programManagementAccountIdentifier is refused
    with the exact entitlement AccessDeniedException for a caller without an active AWS Partner benefit,
    and ListRelationships is denied the same way."""
    client = ctx.client("partnercentral-channel")
    fake_pma_id = "pma-1111111111111"
    associated_account_id = _FOREIGN_ACCOUNT

    def _attempt():
        return client.create_relationship(
            catalog=CATALOG,
            associationType="END_CUSTOMER",
            programManagementAccountIdentifier=fake_pma_id,
            associatedAccountId=associated_account_id,
            displayName=ctx.unique_name("sim2real-rel-")[:30],
            sector="COMMERCIAL",
        )

    code, msg = _error_code_and_message(_attempt)
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    assert msg == BENEFIT_DENIED, (
        f"expected the exact partner-benefit denial message, got {msg!r}"
    )

    def _list_attempt():
        return client.list_relationships(
            catalog=CATALOG, associatedAccountIds=[associated_account_id], maxResults=100
        )

    list_code, list_msg = _error_code_and_message(_list_attempt)
    assert list_code == "AccessDeniedException", (
        f"expected the same entitlement gate on the read path, got {list_code}"
    )
    assert list_msg == BENEFIT_DENIED, (
        f"expected the exact partner-benefit denial message, got {list_msg!r}"
    )


# A documentation placeholder account id: a made-up id could be a real account someone else owns.
_FOREIGN_ACCOUNT = "111122223333"


def _error_code_and_message(fn):
    """Call fn(); return its botocore Error code and message. An unexpected SUCCESS raises, because
    a target ACCEPTING a call real AWS denies is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS denies this call, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
