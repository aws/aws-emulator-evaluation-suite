"""artifact-describe-after-delete-rejected."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "artifact-describe-after-delete-rejected"
GROUP = "representation"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeArtifact and UpdateArtifact on a deleted artifact fail with ResourceNotFound and their
    exact messages and ListArtifacts no longer shows it, while a live artifact still describes."""
    sm = ctx.client("sagemaker")

    # Setup: create an artifact, then remove it -- the one thing we break.
    deleted_arn = sm.create_artifact(
        Source={"SourceUri": "s3://sim2real-bucket/to-be-deleted"},
        ArtifactType="sim2real-test-artifact",
    )["ArtifactArn"]
    sm.delete_artifact(ArtifactArn=deleted_arn)

    describe_err = _client_error(lambda: sm.describe_artifact(ArtifactArn=deleted_arn))
    assert describe_err["Code"] == "ResourceNotFound", f"expected ResourceNotFound, got {describe_err!r}"
    expected_describe = f"Artifact '{deleted_arn}' does not exist."
    assert describe_err["Message"] == expected_describe, (
        f"expected message {expected_describe!r}, got {describe_err.get('Message')!r}"
    )

    # Effect absent: it must not show up in a listing either.
    listed_arns = {
        a["ArtifactArn"]
        for a in sm.list_artifacts(SourceUri="s3://sim2real-bucket/to-be-deleted")["ArtifactSummaries"]
    }
    assert deleted_arn not in listed_arns, "deleted artifact still visible via ListArtifacts"

    # A mutation on the dead id must also be rejected, not just a read.
    update_err = _client_error(
        lambda: sm.update_artifact(ArtifactArn=deleted_arn, ArtifactName="sim2real-post-delete-update")
    )
    assert update_err["Code"] == "ResourceNotFound", (
        f"expected UpdateArtifact on a deleted artifact to reject with ResourceNotFound, got {update_err!r}"
    )
    expected_update = f"Artifact '{deleted_arn}' does not exist."
    assert update_err["Message"] == expected_update, (
        f"expected message {expected_update!r}, got {update_err.get('Message')!r}"
    )

    # Positive control: an artifact we do NOT delete describes fine, in the same file/run.
    live_arn = sm.create_artifact(
        Source={"SourceUri": "s3://sim2real-bucket/still-live"},
        ArtifactType="sim2real-test-artifact",
    )["ArtifactArn"]
    ctx.on_cleanup(lambda: sm.delete_artifact(ArtifactArn=live_arn))
    desc = sm.describe_artifact(ArtifactArn=live_arn)
    assert desc["ArtifactArn"] == live_arn
    assert desc["Source"]["SourceUri"] == "s3://sim2real-bucket/still-live"


def _client_error(fn: Any) -> dict:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
