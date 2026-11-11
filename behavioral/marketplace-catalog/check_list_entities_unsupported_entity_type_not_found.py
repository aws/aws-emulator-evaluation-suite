"""list-entities-unsupported-entity-type-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-entities-unsupported-entity-type-not-found"
GROUP = "error-semantics"
SERVICES = ["marketplace-catalog"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListEntities refuses a letters-only EntityType that names no real entity type with
    ValidationException and its exact message, while a supported EntityType returns a list.
    """
    # The Marketplace Catalog API is served only in us-east-1, so every target is called there.
    mp = ctx.client("marketplace-catalog", region="us-east-1")

    code, msg = _error_code(
        lambda: mp.list_entities(Catalog="AWSMarketplace", EntityType="Frobnicator")
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}: {msg}"
    assert msg == "[Requested entity type 'Frobnicator' is invalid.]", msg

    # positive control: a real, supported entity type succeeds.
    resp = mp.list_entities(Catalog="AWSMarketplace", EntityType="AmiProduct", MaxResults=1)
    assert "EntitySummaryList" in resp, f"expected EntitySummaryList in response, got keys {list(resp)}"


def _error_code(fn):
    """Call fn(); return (code, message) from its ClientError. An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
