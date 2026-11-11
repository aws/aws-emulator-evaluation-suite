"""batch-describe-entities-invalid-entity-id-pattern-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-describe-entities-invalid-entity-id-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["marketplace-catalog"]
ENTITY_ID_PATTERN = r"^[a-zA-Z0-9][.a-zA-Z0-9/-]+[a-zA-Z0-9]$"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """BatchDescribeEntities reports an EntityId outside the pattern per item in Errors as
    ValidationException, and a well-formed missing id as ResourceNotFoundException, each with its
    exact message, without a request-level exception.
    """
    # The Marketplace Catalog API is served only in us-east-1, so every target is called there.
    mp = ctx.client("marketplace-catalog", region="us-east-1")

    resp = mp.batch_describe_entities(
        EntityRequestList=[{"Catalog": "AWSMarketplace", "EntityId": "bad entity id!"}]
    )
    entry = resp.get("Errors", {}).get("bad entity id!")
    assert entry is not None, f"expected a per-item error for the malformed EntityId, got {resp}"
    assert entry["ErrorCode"] == "ValidationException", entry
    assert entry["ErrorMessage"] == (
        f"Requested entity id 'bad entity id!' is invalid. It should match with {ENTITY_ID_PATTERN}."
    ), entry

    good_id = "prod-" + ctx.unique_name("sim2realbehav").replace("-", "")
    resp = mp.batch_describe_entities(
        EntityRequestList=[{"Catalog": "AWSMarketplace", "EntityId": good_id}]
    )
    good_entry = resp.get("Errors", {}).get(good_id)
    assert good_entry is not None, f"expected a per-item error for the unknown well-formed id, got {resp}"
    assert good_entry["ErrorCode"] == "ResourceNotFoundException", (
        f"a well-formed EntityId that merely doesn't exist must fail with ResourceNotFoundException, "
        f"not the pattern-validation error the malformed id above gets -- otherwise this check cannot "
        f"tell 'rejects malformed patterns' from 'rejects every EntityId': got {good_entry}"
    )
    assert good_entry["ErrorMessage"] == f"Requested entity '{good_id}' does not exist.", good_entry


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
