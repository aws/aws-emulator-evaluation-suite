"""revision-list-and-delete-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "revision-list-and-delete-lifecycle"
GROUP = "lifecycle"
SERVICES = ["dataexchange"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDataSetRevisions reflects every revision under a data set, and DeleteRevision
    actually removes just the targeted one (siblings and the data set are unaffected): an
    independent read and a mutation on the deleted id both fail not-found afterward."""
    dx = ctx.client("dataexchange")
    dataset_id = _create_dataset(ctx, dx)

    keep_id = _create_revision(ctx, dx, dataset_id, "keep-me")
    doomed = dx.create_revision(DataSetId=dataset_id, Comment="delete-me", Tags={"sim2real-check": CHECK})
    doomed_id = doomed["Id"]

    listed_before = {r["Id"] for r in dx.list_data_set_revisions(DataSetId=dataset_id)["Revisions"]}
    assert {keep_id, doomed_id}.issubset(listed_before), (
        f"expected both {keep_id} and {doomed_id} in ListDataSetRevisions, got {listed_before}"
    )

    dx.delete_revision(DataSetId=dataset_id, RevisionId=doomed_id)

    listed_after = {r["Id"] for r in dx.list_data_set_revisions(DataSetId=dataset_id)["Revisions"]}
    assert keep_id in listed_after, f"expected surviving revision {keep_id} still in ListDataSetRevisions, got {listed_after}"
    assert doomed_id not in listed_after, f"expected deleted revision {doomed_id} gone from ListDataSetRevisions, got {listed_after}"

    code, message = _error(lambda: dx.get_revision(DataSetId=dataset_id, RevisionId=doomed_id))
    assert code == "ResourceNotFoundException", f"expected GetRevision on deleted id to be ResourceNotFoundException, got {code}"
    assert message == "The requested resource was not found.", f"expected the exact refusal message, got {message!r}"

    # A mutation on the dead id must also fail, not just a read.
    update_code, update_message = _error(
        lambda: dx.update_revision(DataSetId=dataset_id, RevisionId=doomed_id, Comment="should-not-apply")
    )
    assert update_code == "ResourceNotFoundException", (
        f"expected UpdateRevision on deleted id to be ResourceNotFoundException, got {update_code}"
    )
    assert update_message == "The requested resource was not found.", f"expected the exact refusal message, got {update_message!r}"

    # The surviving revision and its parent data set are both still reachable.
    still_there = dx.get_revision(DataSetId=dataset_id, RevisionId=keep_id)
    assert still_there["Comment"] == "keep-me", f"expected surviving revision to keep its comment, got {still_there['Comment']!r}"
    got_dataset_id = dx.get_data_set(DataSetId=dataset_id)["Id"]
    assert got_dataset_id == dataset_id, f"expected parent data set {dataset_id} still reachable, got {got_dataset_id}"


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises,
    because an emulator ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_dataset(ctx, dx) -> str:
    name = ctx.unique_name("sim2real-dx-ds-")
    ds = dx.create_data_set(
        AssetType="S3_SNAPSHOT",
        Description="sim2real check",
        Name=name,
        Tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: dx.delete_data_set(DataSetId=ds["Id"]))
    return ds["Id"]


def _create_revision(ctx, dx, dataset_id: str, comment: str) -> str:
    rev = dx.create_revision(DataSetId=dataset_id, Comment=comment, Tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: dx.delete_revision(DataSetId=dataset_id, RevisionId=rev["Id"]))
    return rev["Id"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
