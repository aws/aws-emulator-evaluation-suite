"""add-association-missing-source-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "add-association-missing-source-not-found"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddAssociation from a never-created artifact ARN to a real context fails with ResourceNotFound
    and the exact message and records no association, while a real artifact as the source is
    associated and listed."""
    sm = ctx.client("sagemaker")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    context_name = ctx.unique_name("sim2real-behav-ctx-")
    context_arn = sm.create_context(
        ContextName=context_name,
        Source={"SourceUri": f"sim2real://{context_name}"},
        ContextType="sim2real-behav-context",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["ContextArn"]
    ctx.on_cleanup(lambda: sm.delete_context(ContextName=context_name))

    bogus_source_arn = (
        f"arn:aws:sagemaker:{ctx.region}:{account_id}:artifact/"
        "deadbeefdeadbeefdeadbeefdeadbeef"
    )

    err = _client_error(
        lambda: sm.add_association(
            SourceArn=bogus_source_arn, DestinationArn=context_arn
        )
    )
    assert err["Code"] == "ResourceNotFound", f"expected ResourceNotFound, got {err!r}"
    expected_message = f"Resource '{bogus_source_arn}' does not exist."
    assert err["Message"] == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    # Effect absent: no association was recorded against the (real) destination.
    assocs = sm.list_associations(DestinationArn=context_arn)["AssociationSummaries"]
    assert assocs == [], f"expected no associations, found {assocs}"

    # Positive control: a real Artifact as the source succeeds.
    artifact_name = ctx.unique_name("sim2real-behav-art-")
    artifact_arn = sm.create_artifact(
        ArtifactName=artifact_name,
        Source={"SourceUri": f"s3://sim2real-behav-bucket/{artifact_name}"},
        ArtifactType="sim2real-behav-artifact",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["ArtifactArn"]
    ctx.on_cleanup(lambda: sm.delete_artifact(ArtifactArn=artifact_arn))

    sm.add_association(SourceArn=artifact_arn, DestinationArn=context_arn)
    ctx.on_cleanup(
        lambda: sm.delete_association(SourceArn=artifact_arn, DestinationArn=context_arn)
    )

    assocs_after = sm.list_associations(DestinationArn=context_arn)["AssociationSummaries"]
    assert any(a["SourceArn"] == artifact_arn for a in assocs_after), (
        f"expected {artifact_arn} among associations to {context_arn}, found {assocs_after}"
    )


def _client_error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
