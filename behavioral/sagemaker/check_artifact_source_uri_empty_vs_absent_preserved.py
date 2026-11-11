"""artifact-source-uri-empty-vs-absent-preserved."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "artifact-source-uri-empty-vs-absent-preserved"
GROUP = "representation"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateArtifact rejects an empty and an absent Source.SourceUri with distinct
    ValidationException messages and persists no artifact, while a real SourceUri succeeds."""
    sm = ctx.client("sagemaker")
    # botocore enforces SourceUri's required/min-length locally; disable it so SageMaker validates.
    raw_sm = ctx.client("sagemaker", config=Config(parameter_validation=False))

    empty_type = ctx.unique_name("sim2real-sm-artifact-empty-")
    code_empty, message_empty = _error(lambda: raw_sm.create_artifact(
        ArtifactType=empty_type,
        Source={"SourceUri": ""},
    ))
    assert code_empty == "ValidationException", (
        f"expected ValidationException for an explicit empty-string SourceUri, got {code_empty!r}"
    )
    expected_empty = (
        "1 validation error detected: Value '' at 'source.sourceUri' failed to satisfy constraint: "
        "Member must have length greater than or equal to 1"
    )
    assert message_empty == expected_empty, f"expected message {expected_empty!r}, got {message_empty!r}"

    absent_type = ctx.unique_name("sim2real-sm-artifact-absent-")
    code_absent, message_absent = _error(lambda: raw_sm.create_artifact(
        ArtifactType=absent_type,
        Source={"SourceTypes": [{"SourceIdType": "Custom", "Value": "v1"}]},
    ))
    assert code_absent == "ValidationException", (
        f"expected ValidationException for a Source with no SourceUri key, got {code_absent!r}"
    )
    expected_absent = (
        "1 validation error detected: Value null at 'source.sourceUri' failed to satisfy constraint: "
        "Member must not be null"
    )
    assert message_absent == expected_absent, f"expected message {expected_absent!r}, got {message_absent!r}"

    good_name = ctx.unique_name("sim2real-sm-artifact-good-")
    good_arn = sm.create_artifact(
        ArtifactName=good_name,
        ArtifactType="DataSet",
        Source={"SourceUri": f"s3://sim2real-fixture-bucket/{good_name}/data.csv"},
    )["ArtifactArn"]
    ctx.on_cleanup(lambda: sm.delete_artifact(ArtifactArn=good_arn))
    desc = sm.describe_artifact(ArtifactArn=good_arn)
    assert desc["ArtifactName"] == good_name, (
        f"expected artifact name {good_name!r}, got {desc.get('ArtifactName')!r}"
    )

    # Neither rejected call persisted an artifact -- an independent read at the destination.
    for artifact_type in (empty_type, absent_type):
        listed = sm.list_artifacts(ArtifactType=artifact_type)["ArtifactSummaries"]
        assert not listed, f"a rejected create_artifact call for {artifact_type!r} was persisted: {listed}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
