"""add-association-source-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "add-association-source-not-found"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AddAssociation from a real Artifact to a well-formed but nonexistent Action ARN returns
    ResourceNotFound with the exact message, records nothing, and leaves the existing
    Artifact-to-Action association intact."""
    sm = ctx.client("sagemaker")

    artifact_name = ctx.unique_name("sim2real-assoc-artifact-")
    action_name = ctx.unique_name("sim2real-assoc-action-")

    artifact_arn = sm.create_artifact(
        ArtifactName=artifact_name,
        Source={"SourceUri": f"s3://sim2real-behavioral/{artifact_name}"},
        ArtifactType="DataSet",
    )["ArtifactArn"]
    ctx.on_cleanup(lambda: sm.delete_artifact(ArtifactArn=artifact_arn))

    sm.create_action(
        ActionName=action_name,
        Source={"SourceUri": f"s3://sim2real-behavioral/{action_name}", "SourceType": "Test"},
        ActionType="ModelDeployment",
    )
    action_arn = sm.describe_action(ActionName=action_name)["ActionArn"]
    ctx.on_cleanup(lambda: sm.delete_action(ActionName=action_name))

    sm.add_association(SourceArn=artifact_arn, DestinationArn=action_arn, AssociationType="ContributedTo")
    ctx.on_cleanup(lambda: sm.delete_association(SourceArn=artifact_arn, DestinationArn=action_arn))

    before = sm.list_associations(SourceArn=artifact_arn)["AssociationSummaries"]
    assert len(before) == 1 and before[0]["DestinationArn"] == action_arn, (
        f"expected the positive-control association to exist, got {before!r}"
    )

    bogus_destination = (
        f"arn:aws:sagemaker:{ctx.region}:{_account_id(ctx)}:action/sim2real-does-not-exist-xyz"
    )
    err = _client_error(
        lambda: sm.add_association(SourceArn=artifact_arn, DestinationArn=bogus_destination)
    )
    assert err["Code"] == "ResourceNotFound", f"expected ResourceNotFound, got {err!r}"
    expected_message = f"Resource '{bogus_destination}' does not exist."
    assert err["Message"] == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    after = sm.list_associations(SourceArn=artifact_arn)["AssociationSummaries"]
    assert len(after) == 1 and after[0]["DestinationArn"] == action_arn, (
        f"positive-control association was disturbed by the rejected call: {after!r}"
    )


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _client_error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
