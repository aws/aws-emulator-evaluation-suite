"""lineage-entity-association-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lineage-entity-association-lifecycle"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting a lineage entity that is the source of a live association is refused, not cascaded;
    after DeleteAssociation it deletes cleanly and unrelated associations are left untouched."""
    sm = ctx.client("sagemaker")

    action_name = ctx.unique_name("sim2real-behav-action-")
    context_name = ctx.unique_name("sim2real-behav-context-")

    resource_tags = [{"Key": "sim2real-behav-check", "Value": CHECK}]

    action_arn = sm.create_action(
        ActionName=action_name,
        Source={"SourceUri": f"s3://sim2real-behav-lineage/{action_name}"},
        ActionType="ModelDeployment",
        Tags=resource_tags,
    )["ActionArn"]
    action_deleted = False

    def _cleanup_action():
        if not action_deleted:
            sm.delete_action(ActionName=action_name)

    ctx.on_cleanup(_cleanup_action)

    context_arn = sm.create_context(
        ContextName=context_name,
        Source={"SourceUri": f"s3://sim2real-behav-lineage/{context_name}", "SourceType": "Endpoint"},
        ContextType="Endpoint",
        Tags=resource_tags,
    )["ContextArn"]
    ctx.on_cleanup(lambda: _delete_context_quiet(sm, context_name))

    artifact_arn = sm.create_artifact(
        Source={"SourceUri": "s3://sim2real-behav-lineage/artifact-1", "SourceTypes": [{"SourceIdType": "Custom", "Value": "1"}]},
        ArtifactType="Model",
        Tags=resource_tags,
    )["ArtifactArn"]
    ctx.on_cleanup(lambda: _delete_artifact_quiet(sm, artifact_arn))

    # action -> context
    sm.add_association(SourceArn=action_arn, DestinationArn=context_arn, AssociationType="ContributedTo")
    ctx.on_cleanup(lambda: _delete_association_quiet(sm, action_arn, context_arn))
    # context -> artifact (independent of the action)
    sm.add_association(SourceArn=context_arn, DestinationArn=artifact_arn, AssociationType="Produced")
    ctx.on_cleanup(lambda: _delete_association_quiet(sm, context_arn, artifact_arn))

    n = _count_associations(sm, source_arn=action_arn)
    assert n == 1, f"expected exactly 1 association sourced from the action, got {n}"
    n = _count_associations(sm, source_arn=context_arn)
    assert n == 1, f"expected exactly 1 association sourced from the context, got {n}"

    # Deleting an entity that is still the SOURCE of a live association is rejected outright
    # (referential-integrity guard), not silently cascaded.
    code, message = _error(lambda: sm.delete_action(ActionName=action_name))
    assert code == "ValidationException", (
        f"expected DeleteAction on an entity that is still a live association source to be "
        f"rejected with ValidationException, got {code!r}"
    )
    expected_message = "Cannot delete entity with associations."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    n = _count_associations(sm, source_arn=action_arn)
    assert n == 1, f"the rejected delete must not have removed the association; got count {n}"

    # Removing the association first unblocks the delete.
    sm.delete_association(SourceArn=action_arn, DestinationArn=context_arn)
    n = _count_associations(sm, source_arn=action_arn)
    assert n == 0, f"expected 0 associations sourced from the action after DeleteAssociation, got {n}"

    sm.delete_action(ActionName=action_name)
    action_deleted = True

    code, message = _error(lambda: sm.describe_action(ActionName=action_name))
    assert code == "ResourceNotFound", (
        f"expected DescribeAction on the deleted action to return ResourceNotFound, got {code!r}"
    )
    expected_message = f"Action '{action_arn}' does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The association whose SOURCE was the deleted action is gone...
    n = _count_associations(sm, destination_arn=context_arn)
    assert n == 0, f"expected 0 associations into the context after its source action was deleted, got {n}"
    # ...but the unrelated association sourced from the still-existing context persists.
    n = _count_associations(sm, source_arn=context_arn)
    assert n == 1, f"expected the unrelated context->artifact association to survive, got count {n}"


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _count_associations(sm, source_arn: str | None = None, destination_arn: str | None = None) -> int:
    kwargs = {}
    if source_arn is not None:
        kwargs["SourceArn"] = source_arn
    if destination_arn is not None:
        kwargs["DestinationArn"] = destination_arn
    resp = sm.list_associations(**kwargs)
    return len(resp.get("AssociationSummaries", []))


def _delete_association_quiet(sm, source_arn: str, destination_arn: str) -> None:
    try:
        sm.delete_association(SourceArn=source_arn, DestinationArn=destination_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _delete_context_quiet(sm, context_name: str) -> None:
    try:
        sm.delete_context(ContextName=context_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _delete_artifact_quiet(sm, artifact_arn: str) -> None:
    try:
        sm.delete_artifact(ArtifactArn=artifact_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
