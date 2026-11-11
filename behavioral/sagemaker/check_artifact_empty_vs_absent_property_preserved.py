"""artifact-empty-vs-absent-property-preserved."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "artifact-empty-vs-absent-property-preserved"
GROUP = "representation"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateArtifact with an empty-string property value fails with ValidationException and the exact
    message and persists nothing, and DescribeArtifact of an artifact created without a property
    returns no key for it: absent and empty are never collapsed."""
    sm = ctx.client("sagemaker")

    source_uri = f"s3://sim2real-behav-bucket/{ctx.unique_name('artifact-')}/data"
    rejected_uri = source_uri + "/rejected"

    # Negative: an explicit empty-string property value is a validation error.
    err = _client_error(lambda: sm.create_artifact(
        Source={"SourceUri": rejected_uri},
        ArtifactType="DataSet",
        Properties={"empty_prop": "", "present_prop": "some-value"},
    ))
    assert err["Code"] == "ValidationException", f"expected ValidationException for empty property value, got {err!r}"
    expected_message = (
        "1 validation error detected: Value '{empty_prop=, present_prop=some-value}' at 'properties' "
        "failed to satisfy constraint: Map value must satisfy constraint: [Member must have length "
        "less than or equal to 4096, Member must have length greater than or equal to 1, Member must "
        "satisfy regular expression pattern: .*]"
    )
    assert err["Message"] == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    # Effect-absent: the rejected call must not have materialized an artifact --
    # an independent read (ListArtifacts, not the failed create's own response) at
    # the exact source URI it would have used finds nothing.
    rejected_matches = sm.list_artifacts(SourceUri=rejected_uri).get("ArtifactSummaries", [])
    assert rejected_matches == [], f"rejected create must not persist an artifact, found {rejected_matches!r}"

    # Positive control: the same call without the empty-string property succeeds,
    # and the property that was never supplied is fully absent on describe.
    artifact_arn = sm.create_artifact(
        Source={"SourceUri": source_uri},
        ArtifactType="DataSet",
        Properties={"present_prop": "some-value"},
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["ArtifactArn"]
    ctx.on_cleanup(lambda: _delete_artifact(sm, artifact_arn))

    described = sm.describe_artifact(ArtifactArn=artifact_arn)
    properties = described.get("Properties", {})

    assert properties.get("present_prop") == "some-value"
    assert "empty_prop" not in properties, "a never-set property must not materialize as a key"
    assert "never_set_prop" not in properties, "an absent property must not materialize as a key"


def _client_error(fn):
    from botocore.exceptions import ClientError as _CE
    try:
        result = fn()
    except _CE as err:
        return err.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_artifact(sm, artifact_arn):
    try:
        sm.delete_artifact(ArtifactArn=artifact_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
