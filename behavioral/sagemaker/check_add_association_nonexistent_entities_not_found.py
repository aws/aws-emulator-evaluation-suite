"""add-association-nonexistent-entities-not-found."""
from __future__ import annotations

import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "add-association-nonexistent-entities-not-found"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AddAssociation against a destination ARN that does not exist returns
    ResourceNotFound and creates no association, while associating two real
    lineage entities still succeeds (positive control in the same file)."""
    sm = ctx.client("sagemaker")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    source_arn = sm.create_artifact(
        Source={"SourceUri": f"s3://sim2real-bucket/{ctx.unique_name('src-')}"},
        ArtifactType="DataSet",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["ArtifactArn"]
    ctx.on_cleanup(lambda: _delete_artifact_quiet(sm, source_arn))

    dest_arn = sm.create_artifact(
        Source={"SourceUri": f"s3://sim2real-bucket/{ctx.unique_name('dst-')}"},
        ArtifactType="DataSet",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["ArtifactArn"]
    ctx.on_cleanup(lambda: _delete_artifact_quiet(sm, dest_arn))

    fake_dest_arn = (
        f"arn:aws:sagemaker:{ctx.region}:{account_id}:artifact/{uuid.uuid4().hex}"
    )
    err = _client_error(
        lambda: sm.add_association(
            SourceArn=source_arn, DestinationArn=fake_dest_arn, AssociationType="ContributedTo"
        )
    )
    assert err["Code"] == "ResourceNotFound", f"expected ResourceNotFound, got {err!r}"
    expected_message = f"Resource '{fake_dest_arn}' does not exist."
    assert err["Message"] == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    # (b) effect absent: no association was recorded toward the nonexistent destination.
    # ListAssociations rejects a request that supplies both SourceArn and DestinationArn,
    # so filter on SourceArn and check the destination client-side.
    listing = sm.list_associations(SourceArn=source_arn)["AssociationSummaries"]
    matches = [a for a in listing if a["DestinationArn"] == fake_dest_arn]
    assert matches == [], (
        f"expected no association toward nonexistent destination, got {matches}"
    )

    # (c) positive control: associating two real artifacts succeeds.
    sm.add_association(
        SourceArn=source_arn, DestinationArn=dest_arn, AssociationType="ContributedTo"
    )
    ctx.on_cleanup(
        lambda: _delete_association_quiet(sm, source_arn, dest_arn)
    )
    real_listing = sm.list_associations(SourceArn=source_arn)["AssociationSummaries"]
    real_matches = [a for a in real_listing if a["DestinationArn"] == dest_arn]
    assert len(real_matches) == 1, (
        f"expected the positive-control association to be recorded, got {real_listing}"
    )


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _delete_artifact_quiet(sm, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        sm.delete_artifact(ArtifactArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _delete_association_quiet(sm, source_arn: str, dest_arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        sm.delete_association(SourceArn=source_arn, DestinationArn=dest_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
