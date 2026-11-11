"""start-change-set-duplicate-change-type-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-change-set-duplicate-change-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["marketplace-catalog"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartChangeSet with the same ChangeType twice on one entity is refused with ValidationException and
    its exact message, a single change gets ResourceNotFoundException for the missing entity, and
    ListChangeSets shows no change set left behind.
    """
    # The Marketplace Catalog API is served only in us-east-1, so every target is called there.
    mp = ctx.client("marketplace-catalog", region="us-east-1")

    duplicate_entity_id = "entity-id@1"
    change = {
        "ChangeType": "AddRevisions",
        "Entity": {"Identifier": duplicate_entity_id, "Type": "DataProduct@1.0"},
        "Details": '{"DataSetArn": "data-set-arn", "RevisionArns": ["revision-arn"]}',
    }

    duplicate_change_set_name = ctx.unique_name("sim2real-behav-")

    def _start_duplicate():
        return mp.start_change_set(
            Catalog="AWSMarketplace",
            ChangeSetName=duplicate_change_set_name,
            ChangeSet=[change, dict(change)],
        )

    code, msg = _error_code(_start_duplicate)
    assert code == "ValidationException", f"expected ValidationException, got {code}: {msg}"
    assert msg == (
        "[Requested changes contain multiple changes for the same change type 'AddRevisions' "
        "on entity 'entity-id'. Entity - change type pairs should be unique.]"
    ), msg

    # positive control: a single (non-duplicated) change against the same
    # entity is accepted past the duplicate-type check -- it fails later
    # because the entity doesn't exist, not because of duplication.
    single_change_set_name = ctx.unique_name("sim2real-behav-")

    def _start_single():
        return mp.start_change_set(
            Catalog="AWSMarketplace",
            ChangeSetName=single_change_set_name,
            ChangeSet=[change],
        )

    code2, msg2 = _error_code(_start_single)
    assert code2 == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code2}: {msg2}"
    assert msg2 == "Requested entity 'entity-id' does not exist.", msg2

    # independent read at the destination: neither rejected StartChangeSet
    # call actually created a change set.
    resp = mp.list_change_sets(
        Catalog="AWSMarketplace",
        FilterList=[
            {
                "Name": "ChangeSetName",
                "ValueList": [duplicate_change_set_name, single_change_set_name],
            }
        ],
    )
    assert resp["ChangeSetSummaryList"] == [], (
        "no change set should exist for a rejected StartChangeSet call, got "
        f"{resp['ChangeSetSummaryList']!r}"
    )


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected StartChangeSet to be rejected, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
