"""artifact-lifecycle-create-describe-delete."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "artifact-lifecycle-create-describe-delete"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An Artifact transitions from created to describable to 404 after delete."""
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-artifact-")

    source_uri = f"s3://sim2real-lineage-bucket/{name}/model.tar.gz"
    created = sm.create_artifact(
        ArtifactName=name,
        Source={"SourceUri": source_uri},
        ArtifactType="Model",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    arn = created["ArtifactArn"]
    ctx.on_cleanup(lambda: _delete_artifact_ignore(sm, arn))

    desc = sm.describe_artifact(ArtifactArn=arn)
    assert desc["ArtifactArn"] == arn, f"expected ArtifactArn {arn}, got {desc['ArtifactArn']}"
    assert desc["ArtifactName"] == name, f"expected ArtifactName {name}, got {desc['ArtifactName']}"
    assert desc["ArtifactType"] == "Model", f"expected ArtifactType Model, got {desc['ArtifactType']}"
    assert desc["Source"]["SourceUri"] == source_uri, (
        f"expected SourceUri {source_uri}, got {desc['Source']['SourceUri']}"
    )

    sm.delete_artifact(ArtifactArn=arn)

    code, message = _error(lambda: sm.describe_artifact(ArtifactArn=arn))
    assert code == "ResourceNotFound", f"expected ResourceNotFound after delete, got {code}"
    expected = f"Artifact '{arn}' does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Deleted is also unusable: a mutation against the dead ARN must fail the same way, not
    # silently succeed against a resource that no longer exists.
    update_code, update_message = _error(
        lambda: sm.update_artifact(ArtifactArn=arn, ArtifactName=ctx.unique_name("sim2real-artifact-"))
    )
    assert update_code == "ResourceNotFound", (
        f"expected UpdateArtifact on a deleted artifact to fail ResourceNotFound, got {update_code}"
    )
    expected_update = f"Artifact '{arn}' does not exist."
    assert update_message == expected_update, f"expected message {expected_update!r}, got {update_message!r}"


def _error(fn):
    """Return (code, message) of the call's ClientError; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to fail, but it SUCCEEDED and returned {result!r}")


def _delete_artifact_ignore(sm, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        sm.delete_artifact(ArtifactArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
