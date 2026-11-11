"""add-association-self-reference-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "add-association-self-reference-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddAssociation from an entity to itself succeeds and records a self-referencing lineage
    edge."""
    sm = ctx.client("sagemaker")

    artifact_name = ctx.unique_name("sim2real-behav-artifact-")
    artifact_arn = sm.create_artifact(
        ArtifactName=artifact_name,
        Source={"SourceUri": f"s3://sim2real-behavioral-bucket/{artifact_name}.bin"},
        ArtifactType="DataSet",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["ArtifactArn"]
    ctx.on_cleanup(lambda: sm.delete_artifact(ArtifactArn=artifact_arn))

    resp = sm.add_association(
        SourceArn=artifact_arn,
        DestinationArn=artifact_arn,
        AssociationType="ContributedTo",
    )
    assert resp["SourceArn"] == artifact_arn and resp["DestinationArn"] == artifact_arn, (
        f"expected AddAssociation to accept a self-referencing edge, got {resp!r}"
    )
    ctx.on_cleanup(lambda: _delete_association_quiet(sm, artifact_arn, artifact_arn))

    # independent read at a different operation than the one that mutated: the self-loop is now visible.
    # ListAssociations rejects SourceArn and DestinationArn given together (real AWS: ValidationException
    # "One of Source Arn or Destination Arn is required either both are missing or were supplied"), so
    # list by SourceArn alone and filter client-side for the self edge.
    self_assoc = _self_associations(sm, artifact_arn)
    assert len(self_assoc) == 1, f"expected exactly 1 self-referencing association to be recorded, found {self_assoc!r}"
    assert self_assoc[0]["AssociationType"] == "ContributedTo", (
        f"expected the recorded self-association to keep AssociationType=ContributedTo, got {self_assoc[0]!r}"
    )

    # cross-check: an association between two distinct lineage entities also succeeds, independently of the self-loop
    context_name = ctx.unique_name("sim2real-behav-context-")
    context_arn = sm.create_context(
        ContextName=context_name,
        Source={"SourceUri": f"sim2real://behavioral/{context_name}"},
        ContextType="Endpoint",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["ContextArn"]
    ctx.on_cleanup(lambda: sm.delete_context(ContextName=context_name))

    sm.add_association(SourceArn=artifact_arn, DestinationArn=context_arn, AssociationType="ContributedTo")
    ctx.on_cleanup(lambda: _delete_association_quiet(sm, artifact_arn, context_arn))

    forward = sm.list_associations(DestinationArn=context_arn)["AssociationSummaries"]
    assert len(forward) == 1, f"expected exactly 1 association between distinct entities, found {len(forward)}: {forward!r}"

    # delete proves gone: the self-association is independently removable and its removal does not
    # disturb the unrelated distinct-entity association
    sm.delete_association(SourceArn=artifact_arn, DestinationArn=artifact_arn)
    remaining_self = _self_associations(sm, artifact_arn)
    assert remaining_self == [], f"expected self-association to be gone after delete, found {remaining_self!r}"
    still_forward = sm.list_associations(DestinationArn=context_arn)["AssociationSummaries"]
    assert len(still_forward) == 1, (
        f"deleting the self-association must not disturb the distinct-entity association, found {still_forward!r}"
    )


def _self_associations(sm, arn: str) -> list:
    items = sm.list_associations(SourceArn=arn)["AssociationSummaries"]
    return [a for a in items if a["DestinationArn"] == arn]


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
