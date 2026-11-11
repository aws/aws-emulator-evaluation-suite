"""batch-describe-entities-partial-errors."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-describe-entities-partial-errors"
GROUP = "data-plane"
SERVICES = ["marketplace-catalog"]
ENTITY_ID_PATTERN = r"^[a-zA-Z0-9][.a-zA-Z0-9/-]+[a-zA-Z0-9]$"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """In one BatchDescribeEntities call, a missing id and a malformed id are both absent from
    EntityDetails and reported in Errors as ResourceNotFoundException and ValidationException with
    their exact messages.
    """
    # The Marketplace Catalog API is served only in us-east-1, so every target is called there.
    mp = ctx.client("marketplace-catalog", region="us-east-1")

    missing_id = "prod-" + ctx.unique_name("sim2realbehav").replace("-", "")
    malformed_id = "bad entity id!"
    resp = mp.batch_describe_entities(
        EntityRequestList=[
            {"Catalog": "AWSMarketplace", "EntityId": missing_id},
            {"Catalog": "AWSMarketplace", "EntityId": malformed_id},
        ]
    )

    details = resp.get("EntityDetails", {})
    assert missing_id not in details, "unknown entity must not appear in EntityDetails"
    assert malformed_id not in details, "malformed entity id must not appear in EntityDetails"

    errors = resp.get("Errors", {})
    assert missing_id in errors, f"expected {missing_id!r} to be reported in Errors, got {errors}"
    assert errors[missing_id]["ErrorCode"] == "ResourceNotFoundException", errors[missing_id]
    assert errors[missing_id]["ErrorMessage"] == (
        f"Requested entity '{missing_id}' does not exist."
    ), errors[missing_id]

    assert malformed_id in errors, f"expected {malformed_id!r} to be reported in Errors, got {errors}"
    assert errors[malformed_id]["ErrorCode"] == "ValidationException", (
        f"malformed id must be classified differently than the well-formed-but-missing id, "
        f"got {errors[malformed_id]}"
    )
    assert errors[malformed_id]["ErrorMessage"] == (
        f"Requested entity id '{malformed_id}' is invalid. It should match with {ENTITY_ID_PATTERN}."
    ), errors[malformed_id]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
