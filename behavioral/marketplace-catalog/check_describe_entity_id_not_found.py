"""describe-entity-id-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-entity-id-not-found"
GROUP = "error-semantics"
SERVICES = ["marketplace-catalog"]
ENTITY_ID_PATTERN = r"^[a-zA-Z0-9][.a-zA-Z0-9/-]+[a-zA-Z0-9]$"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeEntity refuses a too-short EntityId with ValidationException and a well-formed nonexistent
    one with ResourceNotFoundException, each with its exact message.
    """
    # The Marketplace Catalog API is served only in us-east-1, so every target is called there.
    mp = ctx.client("marketplace-catalog", region="us-east-1")

    code, msg = _error_code(lambda: mp.describe_entity(Catalog="AWSMarketplace", EntityId="a"))
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert msg == f"[Requested entity id 'a' is invalid. It should match with {ENTITY_ID_PATTERN}.]", msg

    missing_id = "prod-" + ctx.unique_name("sim2realbehav").replace("-", "")
    code2, msg2 = _error_code(lambda: mp.describe_entity(Catalog="AWSMarketplace", EntityId=missing_id))
    assert code2 == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code2}"
    assert msg2 == f"Requested entity '{missing_id}' does not exist.", msg2


def _error_code(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
