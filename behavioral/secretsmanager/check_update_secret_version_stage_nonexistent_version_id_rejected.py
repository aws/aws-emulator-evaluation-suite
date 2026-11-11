"""update-secret-version-stage-nonexistent-version-id-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-secret-version-stage-nonexistent-version-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["secretsmanager"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateSecretVersionStage with a MoveToVersionId that doesn't exist on the secret is rejected."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-secmgr-badstage-")
    created = sm.create_secret(
        Name=name,
        SecretString="stage-guard-value",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    secret_arn = created["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))
    version0 = created["VersionId"]

    bogus_version = str(uuid.uuid4())
    code, message = _error(
        lambda: sm.update_secret_version_stage(
            SecretId=secret_arn, VersionStage="AWSCURRENT", MoveToVersionId=bogus_version, RemoveFromVersionId=version0
        )
    )
    assert code == "ResourceNotFoundException", (
        f"MoveToVersionId={bogus_version!r} does not exist on the secret; expected "
        f"ResourceNotFoundException, got {code!r}"
    )
    expected = f"Secrets Manager can't find the specified secret value for VersionId: {bogus_version}"
    assert message == expected, f"rejection message {message!r}, expected {expected!r}"

    # Effect absent: AWSCURRENT is still on the original version.
    after = sm.describe_secret(SecretId=secret_arn)
    assert "AWSCURRENT" in after["VersionIdsToStages"].get(version0, []), (
        f"the rejected move must leave AWSCURRENT on {version0!r}, got "
        f"{after['VersionIdsToStages']!r}"
    )

    # Positive control: moving AWSCURRENT to a version that genuinely exists succeeds.
    put = sm.put_secret_value(SecretId=secret_arn, SecretString="stage-guard-value-2", VersionStages=["CUSTOMSTAGE"])
    version1 = put["VersionId"]
    sm.update_secret_version_stage(
        SecretId=secret_arn, VersionStage="AWSCURRENT", MoveToVersionId=version1, RemoveFromVersionId=version0
    )
    final = sm.describe_secret(SecretId=secret_arn)
    assert "AWSCURRENT" in final["VersionIdsToStages"].get(version1, []), (
        f"the identical call with a real MoveToVersionId={version1!r} must succeed and move "
        f"AWSCURRENT there, got {final['VersionIdsToStages']!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected UpdateSecretVersionStage with a nonexistent MoveToVersionId to be rejected, "
        f"but it succeeded and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
