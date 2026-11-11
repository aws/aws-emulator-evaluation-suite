"""list-customer-agreements-state-consistency."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-customer-agreements-state-consistency"
GROUP = "data-plane"
SERVICES = ["artifact"]

VALID_STATES = {"ACTIVE", "CUSTOMER_TERMINATED", "AWS_TERMINATED"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListCustomerAgreements returns a customerAgreements list, possibly empty, as no API accepts an
    agreement, and every returned agreement has a CustomerAgreementState value, a well-formed ARN
    and a non-empty type."""
    art = ctx.client("artifact")
    agreements = art.list_customer_agreements(maxResults=300)["customerAgreements"]
    assert isinstance(agreements, list), f"customerAgreements must be a list, got {agreements!r}"

    for agreement in agreements:
        assert agreement["state"] in VALID_STATES, (
            f"unexpected agreement state {agreement['state']!r}; "
            f"expected one of {sorted(VALID_STATES)}"
        )
        assert agreement["arn"].startswith("arn:"), f"malformed arn: {agreement['arn']!r}"
        assert agreement["agreementArn"].startswith("arn:"), (
            f"malformed agreementArn: {agreement['agreementArn']!r}"
        )
        assert isinstance(agreement["type"], str) and agreement["type"], (
            f"type must be a non-empty string, got {agreement['type']!r}"
        )
        assert agreement["awsAccountId"], "awsAccountId must be populated"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
