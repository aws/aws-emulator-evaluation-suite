"""delete-relationship-nonexistent-error."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-relationship-nonexistent-error"
GROUP = "overly-permissive"
SERVICES = ["partnercentral-channel"]

CATALOG = "Sandbox"
BENEFIT_DENIED = (
    "This action requires an active AWS Partner benefit. Register as an AWS Partner "
    "if you haven't already, or contact AWS Partner Central Support."
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteRelationship on a syntactically well-formed but nonexistent
    (identifier, programManagementAccountIdentifier) pair is rejected, never returning
    a false success for a relationship that was never granted to this caller."""
    client = ctx.client("partnercentral-channel")
    fake_pma_id = "pma-1111111111111"
    fake_rel_id = "rs-1111111111111"

    def _attempt():
        client.delete_relationship(
            catalog=CATALOG,
            identifier=fake_rel_id,
            programManagementAccountIdentifier=fake_pma_id,
        )

    code, message = _error_code(_attempt)
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}: {message}"
    assert message == BENEFIT_DENIED, message


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
