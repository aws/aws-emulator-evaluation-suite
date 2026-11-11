"""update-secret-version-stage-move-awscurrent-without-moveto-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "update-secret-version-stage-move-awscurrent-without-moveto-rejected"
GROUP = "concurrency"
SERVICES = ["secretsmanager"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Moving AWSCURRENT to a new version without RemoveFromVersionId is rejected and the label
    stays on its version; the same move with RemoveFromVersionId succeeds."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-stagemove-")
    created = sm.create_secret(Name=name, SecretString="v0")
    arn = created["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True))
    v0 = created["VersionId"]

    v1 = str(uuid.uuid4())
    sm.put_secret_value(
        SecretId=arn, ClientRequestToken=v1, SecretString="v1", VersionStages=["AWSPENDING"]
    )

    # AWSCURRENT is already attached to v0. Trying to move it to v1 without telling
    # Secrets Manager where to remove it from must be rejected.
    code, message = _error(
        lambda: sm.update_secret_version_stage(
            SecretId=arn, VersionStage="AWSCURRENT", MoveToVersionId=v1
        )
    )
    assert code == "InvalidParameterException", f"unexpected rejection code: {code}"
    expected = (
        "The parameter RemoveFromVersionId can't be empty. Staging label AWSCURRENT is "
        f"currently attached to version {v0}, so you must explicitly reference that version "
        "in RemoveFromVersionId."
    )
    assert message == expected, f"rejection message {message!r}, expected {expected!r}"

    # effect absent: AWSCURRENT is still on v0, nothing changed
    desc = sm.describe_secret(SecretId=arn)
    assert "AWSCURRENT" in desc["VersionIdsToStages"][v0]
    assert "AWSCURRENT" not in desc["VersionIdsToStages"].get(v1, [])

    # positive control: the same kind of move, done correctly, succeeds
    sm.update_secret_version_stage(
        SecretId=arn, VersionStage="AWSCURRENT", MoveToVersionId=v1, RemoveFromVersionId=v0
    )
    desc = sm.describe_secret(SecretId=arn)
    assert "AWSCURRENT" in desc["VersionIdsToStages"][v1]
    assert "AWSCURRENT" not in desc["VersionIdsToStages"].get(v0, [])


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
