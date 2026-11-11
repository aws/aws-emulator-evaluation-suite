"""start-change-set-entity-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-change-set-entity-not-found"
GROUP = "state-machine"
SERVICES = ["marketplace-catalog"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartChangeSet refuses a malformed identifier with ValidationException and a change to a
    nonexistent entity with ResourceNotFoundException, each with its exact message, and creates no
    change set.
    """
    # The Marketplace Catalog API is served in us-east-1 only, so the client pins that region.
    mp = ctx.client("marketplace-catalog", region="us-east-1")

    change_set_name = ctx.unique_name("sim2real-behav-")
    missing_entity = "prod-" + ctx.unique_name("sim2realbehav").replace("-", "")
    missing_entity_id = missing_entity + "@1"

    def _start_malformed():
        # Discriminating control: a malformed identifier (disallowed '#' char) must be
        # rejected for a DIFFERENT, specific reason than a well-formed-but-missing one --
        # otherwise "rejects a missing entity" is indistinguishable from "rejects every
        # StartChangeSet call".
        mp.start_change_set(
            Catalog="AWSMarketplace",
            ChangeSetName=ctx.unique_name("sim2real-behav-"),
            ChangeSet=[
                {
                    "ChangeType": "AddRevisions",
                    "Entity": {"Identifier": "bad#identifier", "Type": "DataProduct@1.0"},
                    "Details": '{"DataSetArn": "data-set-arn", "RevisionArns": ["revision-arn"]}',
                }
            ],
        )

    code0, msg0 = _error_code(_start_malformed)
    assert code0 == "ValidationException", f"expected ValidationException, got {code0}: {msg0}"
    expected0 = (
        "[Requested entity identifier 'bad#identifier' is invalid. It should match with "
        + r"(^[a-zA-Z0-9][.a-zA-Z0-9/-]+[a-zA-Z0-9](@\d+)?$)|(^\$[a-zA-Z]{1,72}\.Entity\.Identifier$)"
        + ".]"
    )
    assert msg0 == expected0, f"expected message {expected0!r}, got {msg0!r}"

    def _start():
        mp.start_change_set(
            Catalog="AWSMarketplace",
            ChangeSetName=change_set_name,
            ChangeSet=[
                {
                    "ChangeType": "AddRevisions",
                    "Entity": {"Identifier": missing_entity_id, "Type": "DataProduct@1.0"},
                    "Details": '{"DataSetArn": "data-set-arn", "RevisionArns": ["revision-arn"]}',
                }
            ],
        )

    code, msg = _error_code(_start)
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}: {msg}"
    expected = f"Requested entity '{missing_entity}' does not exist."
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    resp = mp.list_change_sets(
        Catalog="AWSMarketplace",
        FilterList=[{"Name": "ChangeSetName", "ValueList": [change_set_name]}],
    )
    assert resp["ChangeSetSummaryList"] == [], "no change set should have been created"


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
