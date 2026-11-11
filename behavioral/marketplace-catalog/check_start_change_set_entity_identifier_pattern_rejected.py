"""start-change-set-entity-identifier-pattern-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-change-set-entity-identifier-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["marketplace-catalog"]
ENTITY_IDENTIFIER_PATTERN = r"(^[a-zA-Z0-9][.a-zA-Z0-9/-]+[a-zA-Z0-9](@\d+)?$)|(^\$[a-zA-Z]{1,72}\.Entity\.Identifier$)"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartChangeSet refuses an Entity.Identifier containing '#' with ValidationException, while a valid
    but nonexistent identifier gets ResourceNotFoundException, each with its exact message.
    """
    # The Marketplace Catalog API is served only in us-east-1, so every target is called there.
    mp = ctx.client("marketplace-catalog", region="us-east-1")

    bad_change = {
        "ChangeType": "AddRevisions",
        "Entity": {"Identifier": "bad#identifier", "Type": "DataProduct@1.0"},
        "Details": '{"DataSetArn": "data-set-arn", "RevisionArns": ["revision-arn"]}',
    }
    code, msg = _error_code(
        lambda: mp.start_change_set(
            Catalog="AWSMarketplace",
            ChangeSetName=ctx.unique_name("sim2real-behav-"),
            ChangeSet=[bad_change],
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert msg == (
        f"[Requested entity identifier 'bad#identifier' is invalid. It should match with {ENTITY_IDENTIFIER_PATTERN}.]"
    ), msg

    good_change = dict(bad_change)
    good_id = "prod-" + ctx.unique_name("sim2realbehav").replace("-", "")
    good_change["Entity"] = {
        "Identifier": good_id + "@1",
        "Type": "DataProduct@1.0",
    }
    code2, msg2 = _error_code(
        lambda: mp.start_change_set(
            Catalog="AWSMarketplace",
            ChangeSetName=ctx.unique_name("sim2real-behav-"),
            ChangeSet=[good_change],
        )
    )
    assert code2 == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code2}"
    assert msg2 == f"Requested entity '{good_id}' does not exist.", msg2


def _error_code(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
