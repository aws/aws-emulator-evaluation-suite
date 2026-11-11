"""artifact-create-describe-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "artifact-create-describe-delete"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A lineage Artifact's source URI/type persist across create->describe and the
    resource is gone (404) after delete."""
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-behav-artifact-")
    source_uri = f"s3://sim2real-behav-bucket/{name}"

    create_resp = sm.create_artifact(
        ArtifactName=name,
        ArtifactType="DataSet",
        Source={
            "SourceUri": source_uri,
            "SourceTypes": [{"SourceIdType": "Custom", "Value": "sim2real-behav"}],
        },
        Properties={"env": "test"},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    arn = create_resp["ArtifactArn"]
    ctx.on_cleanup(lambda: _delete_artifact_best_effort(sm, arn))

    described = sm.describe_artifact(ArtifactArn=arn)
    assert described["ArtifactName"] == name, (
        f"expected ArtifactName {name!r}, got {described['ArtifactName']!r}"
    )
    assert described["Source"]["SourceUri"] == source_uri, (
        f"expected SourceUri {source_uri!r}, got {described['Source']['SourceUri']!r}"
    )
    assert described["Source"]["SourceTypes"][0]["SourceIdType"] == "Custom", (
        f"expected SourceIdType 'Custom', got {described['Source']['SourceTypes'][0]['SourceIdType']!r}"
    )
    assert described["ArtifactType"] == "DataSet", (
        f"expected ArtifactType 'DataSet', got {described['ArtifactType']!r}"
    )
    assert described["Properties"] == {"env": "test"}, (
        f"expected Properties {{'env': 'test'}}, got {described['Properties']!r}"
    )

    sm.delete_artifact(ArtifactArn=arn)

    describe_err = _client_error(lambda: sm.describe_artifact(ArtifactArn=arn))
    assert describe_err["Code"] == "ResourceNotFound", f"expected ResourceNotFound after delete, got {describe_err!r}"
    expected_describe = f"Artifact '{arn}' does not exist."
    assert describe_err["Message"] == expected_describe, (
        f"expected message {expected_describe!r}, got {describe_err.get('Message')!r}"
    )

    # A mutation on the dead id must also fail, not just the read.
    update_err = _client_error(lambda: sm.update_artifact(ArtifactArn=arn, ArtifactName=f"{name}-renamed"))
    assert update_err["Code"] == "ResourceNotFound", (
        f"expected UpdateArtifact on a deleted artifact to fail ResourceNotFound, got {update_err!r}"
    )
    expected_update = f"Artifact '{arn}' does not exist."
    assert update_err["Message"] == expected_update, (
        f"expected message {expected_update!r}, got {update_err.get('Message')!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore error dict (Code and Message). An unexpected SUCCESS raises,
    because an emulator accepting a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected this call to fail, but it SUCCEEDED and returned {result!r}")


def _delete_artifact_best_effort(sm, arn):
    try:
        sm.delete_artifact(ArtifactArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
