"""list-agreement-charges-empty-response-structure."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "list-agreement-charges-empty-response-structure"
GROUP = "list-semantics"
SERVICES = ["marketplace-agreement"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListAgreementCharges, scoped to an agreementId no charge could exist against, returns a
    well-formed empty 'items' list and no nextToken -- never an error, a missing key, or a
    phantom page token."""
    # marketplace-agreement (agreement-marketplace) has no us-west-2 endpoint in botocore's
    # endpoints.json -- it exists only in us-east-1. Without this pin the call resolves to
    # https://agreement-marketplace.us-west-2.amazonaws.com/ and dies with EndpointConnectionError.
    mpa = ctx.client("marketplace-agreement", region="us-east-1")
    # A random agreementId has no charges against it in any account, so this needs no
    # pre-existing agreement: catalog+agreementType narrow the (already empty) result further.
    resp = mpa.list_agreement_charges(
        catalog="AWSMarketplace",
        agreementId=str(uuid.uuid4()),
        agreementType="PurchaseAgreement",
        maxResults=5,
    )
    # `isinstance(items, list)` used to be asserted here and was removed: the Smithy model declares
    # `items` a list, so boto3's parser cannot produce anything else on a 2xx. It asserted a
    # property of botocore, not of AWS. The emptiness and the absent nextToken below are the two
    # things the service can actually get wrong.
    items = resp["items"]
    assert items == [], f"a random agreementId has no charges, so items must be empty; got {items!r}"
    assert not resp.get("nextToken"), (
        f"no items returned but nextToken was {resp.get('nextToken')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
