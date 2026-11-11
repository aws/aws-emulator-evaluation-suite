"""list-relationships-access-denied-without-partner-benefit."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-relationships-access-denied-without-partner-benefit"
GROUP = "overly-permissive"
SERVICES = ["partnercentral-channel"]

CATALOG = "Sandbox"
BENEFIT_DENIED = (
    "This action requires an active AWS Partner benefit. Register as an AWS Partner "
    "if you haven't already, or contact AWS Partner Central Support."
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListRelationships is entitlement-gated: a caller with no active AWS Partner
    benefit cannot even read an empty page scoped to a synthetic, nonexistent PMA --
    it is rejected with AccessDeniedException, not a well-formed empty result."""
    client = ctx.client("partnercentral-channel")
    fake_pma_id = "pma-1111111111111"

    def _attempt():
        return client.list_relationships(
            catalog=CATALOG, programManagementAccountIdentifiers=[fake_pma_id], maxResults=100
        )

    code, msg = _error_code_and_message(_attempt)
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    assert msg == BENEFIT_DENIED, (
        f"expected the exact partner-benefit denial message, got {msg!r}"
    )


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
