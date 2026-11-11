"""event-action-requires-entitled-dataset-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "event-action-requires-entitled-dataset-rejected"
GROUP = "overly-permissive"
SERVICES = ["dataexchange"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateEventAction(RevisionPublished) on an OWNED data set fails with ValidationException "Event actions are
    only compatible with Data Sets where the value for Origin is ENTITLED.", on a never-created DataSetId with
    ResourceNotFoundException, and neither call leaves an event action."""
    dx = ctx.client("dataexchange")
    bucket = _create_bucket(ctx)

    # An owned (producer) data set is real, exists, and is readable -- but is not
    # ENTITLED, so it must still be rejected.
    owned_dataset_id = _create_dataset(ctx, dx)
    got_owned = dx.get_data_set(DataSetId=owned_dataset_id)
    assert got_owned["Origin"] == "OWNED", f"expected OWNED origin, got {got_owned.get('Origin')!r}"

    code_owned, message_owned = _error(
        ctx,
        dx,
        lambda: dx.create_event_action(
            Event={"RevisionPublished": {"DataSetId": owned_dataset_id}},
            Action={"ExportRevisionToS3": {"RevisionDestination": {"Bucket": bucket}}},
        ),
    )
    assert code_owned == "ValidationException", (
        f"expected ValidationException for a RevisionPublished event action on an "
        f"OWNED (non-ENTITLED) data set, got {code_owned!r}"
    )
    assert message_owned == (
        "Event actions are only compatible with Data Sets where the value for Origin is ENTITLED."
    ), message_owned

    # A well-formed but never-created DataSetId is rejected too.
    nonexistent_dataset_id = "a" * 38
    code_missing, message_missing = _error(
        ctx,
        dx,
        lambda: dx.create_event_action(
            Event={"RevisionPublished": {"DataSetId": nonexistent_dataset_id}},
            Action={"ExportRevisionToS3": {"RevisionDestination": {"Bucket": bucket}}},
        ),
    )
    assert code_missing == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a never-created "
        f"DataSetId, got {code_missing!r}"
    )
    assert message_missing == "The requested resource was not found.", message_missing

    for source_id in (owned_dataset_id, nonexistent_dataset_id):
        left = dx.list_event_actions(EventSourceId=source_id)["EventActions"]
        assert left == [], f"a rejected request left event actions for {source_id}: {left!r}"


def _error(ctx, dx, fn):
    """Call fn(); return its error code and message. An unexpected SUCCESS raises and any event
    action it managed to create is still torn down."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    ctx.on_cleanup(lambda: dx.delete_event_action(EventActionId=result["Id"]))
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-dx-evt-bad-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    return bucket


def _create_dataset(ctx, dx) -> str:
    name = ctx.unique_name("sim2real-dx-ds-")
    ds = dx.create_data_set(AssetType="S3_SNAPSHOT", Description="sim2real check", Name=name)
    ctx.on_cleanup(lambda: dx.delete_data_set(DataSetId=ds["Id"]))
    return ds["Id"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

