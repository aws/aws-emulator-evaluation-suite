"""update-relationship-nonexistent-error."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-relationship-nonexistent-error"
GROUP = "overly-permissive"
SERVICES = ["partnercentral-channel"]

CATALOG = "Sandbox"
BENEFIT_DENIED = (
    "This action requires an active AWS Partner benefit. Register as an AWS Partner "
    "if you haven't already, or contact AWS Partner Central Support."
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateRelationship on a well-formed nonexistent relationship is refused with the exact
    entitlement AccessDeniedException for a caller without an active AWS Partner benefit, and
    GetRelationship on it is denied the same way."""
    client = ctx.client("partnercentral-channel")
    fake_pma_id = "pma-1111111111111"
    fake_rel_id = "rs-1111111111111"

    def _attempt():
        client.update_relationship(
            catalog=CATALOG,
            identifier=fake_rel_id,
            programManagementAccountIdentifier=fake_pma_id,
            revision="1",
            displayName=ctx.unique_name("sim2real-rel-upd-")[:30],
        )

    code, msg = _error_code(_attempt)
    assert code == "AccessDeniedException", code
    assert msg == BENEFIT_DENIED, msg

    def _independent_read():
        client.get_relationship(
            catalog=CATALOG,
            programManagementAccountIdentifier=fake_pma_id,
            identifier=fake_rel_id,
        )

    read_code, read_msg = _error_code(_independent_read)
    assert read_code == "AccessDeniedException", read_code
    assert read_msg == BENEFIT_DENIED, read_msg


def _error_code(fn):
    """Call fn(); return its botocore Error code and message. An unexpected SUCCESS raises,
    so a target that accepts a call real AWS denies cannot pass as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS denies this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
