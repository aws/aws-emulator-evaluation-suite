"""artifact-lifecycle-transitions."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "artifact-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Artifact persists across DescribeArtifact, and after DeleteArtifact it is both
    unreadable and unmutatable -- not merely absent from one API."""
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-artifact-")
    source_uri = f"s3://sim2real-behavioral-bucket/artifacts/{name}"

    create_resp = sm.create_artifact(
        ArtifactName=name,
        Source={"SourceUri": source_uri, "SourceTypes": [{"SourceIdType": "Custom", "Value": name}]},
        ArtifactType="DataSet",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    artifact_arn = create_resp["ArtifactArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: sm.delete_artifact(ArtifactArn=artifact_arn)))

    described = sm.describe_artifact(ArtifactArn=artifact_arn)
    assert described["ArtifactArn"] == artifact_arn, (
        f"expected ArtifactArn {artifact_arn}, got {described.get('ArtifactArn')!r}"
    )
    assert described["ArtifactType"] == "DataSet", (
        f"expected ArtifactType 'DataSet', got {described.get('ArtifactType')!r}"
    )
    assert described["Source"]["SourceUri"] == source_uri, (
        f"expected SourceUri {source_uri}, got {described.get('Source', {}).get('SourceUri')!r}"
    )

    sm.delete_artifact(ArtifactArn=artifact_arn)

    _poll_until(
        lambda: _describable(sm, artifact_arn),
        lambda visible: visible is False,
        timeout_s=60,
        interval_s=3,
        description="DescribeArtifact to stop describing the artifact after delete",
    )
    code, message = _error(lambda: sm.describe_artifact(ArtifactArn=artifact_arn))
    assert code == "ResourceNotFound", f"expected ResourceNotFound after delete, got {code!r}"
    expected = f"Artifact '{artifact_arn}' does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # A deleted artifact must also reject a mutation, not merely a read -- otherwise
    # "deleted" would mean nothing more than "not describable".
    update_code, update_message = _error(
        lambda: sm.update_artifact(ArtifactArn=artifact_arn, Properties={"probe": "post-delete"})
    )
    assert update_code == "ResourceNotFound", (
        f"expected UpdateArtifact on a deleted artifact to fail with ResourceNotFound, got {update_code!r}"
    )
    expected_update = f"Artifact '{artifact_arn}' does not exist."
    assert update_message == expected_update, f"expected message {expected_update!r}, got {update_message!r}"


def _error(fn):
    """Return (code, message) of the call's ClientError; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to fail, but it SUCCEEDED and returned {result!r}")


def _describable(sm, artifact_arn: str) -> bool:
    """True while DescribeArtifact still answers, False once it reports ResourceNotFound."""
    try:
        sm.describe_artifact(ArtifactArn=artifact_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFound":
            return False
        raise
    return True


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str = "condition"):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s}s; last value: {value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
