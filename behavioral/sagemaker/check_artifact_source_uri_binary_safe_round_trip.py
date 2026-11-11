"""artifact-source-uri-binary-safe-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "artifact-source-uri-binary-safe-round-trip"
GROUP = "representation"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An Artifact SourceUri containing base64/percent-encoded characters is stored and
    returned unchanged by DescribeArtifact -- not re-encoded, decoded, or truncated."""
    sm = ctx.client("sagemaker")

    # A URI-ish string packed with percent-encoding, base64 padding, and reserved characters
    # that a naive re-encode/decode pass would corrupt.
    source_uri = (
        "s3://sim2real-bucket/prefix%2Fwith%20spaces/"
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload==?"
        "versionId=abc%3D%3D%2B%2F&x-amz-meta=%E2%98%82"
    )

    resp = sm.create_artifact(
        Source={"SourceUri": source_uri, "SourceTypes": [{"SourceIdType": "Custom", "Value": "v1"}]},
        ArtifactType="sim2real-test-artifact",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    artifact_arn = resp["ArtifactArn"]
    ctx.on_cleanup(lambda: sm.delete_artifact(ArtifactArn=artifact_arn))

    desc = sm.describe_artifact(ArtifactArn=artifact_arn)
    got_uri = desc["Source"]["SourceUri"]
    assert got_uri == source_uri, (
        f"SourceUri mangled on round-trip: sent {source_uri!r} got {got_uri!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
