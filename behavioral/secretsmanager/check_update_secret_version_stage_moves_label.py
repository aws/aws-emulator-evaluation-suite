"""update-secret-version-stage-moves-label."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

def _force_delete(sm, secret_id):
    try:
        sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

def _create_secret(sm, ctx, name=None, secret_string="initial-value", **kwargs):
    """Create a secret, register its force-delete teardown, and return the raw response."""
    if name is None:
        name = ctx.unique_name("sim2real-behav-" + "secret-")
    params = {"Name": name}
    if secret_string is not None:
        params["SecretString"] = secret_string
    params.update(kwargs)
    resp = sm.create_secret(**params)
    ctx.on_cleanup(lambda: _force_delete(sm, name))
    return resp

CHECK = "update-secret-version-stage-moves-label"
GROUP = 'state-machine'
SERVICES = ['secretsmanager']

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateSecretVersionStage can move AWSCURRENT from one version to another explicitly."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-secret-")
    create_resp = _create_secret(sm, ctx, name=name, secret_string="v1")
    v1 = create_resp["VersionId"]

    put_resp = sm.put_secret_value(SecretId=name, SecretString="v2")
    v2 = put_resp["VersionId"]

    before = sm.get_secret_value(SecretId=name)
    assert before["VersionId"] == v2, (
        f"expected AWSCURRENT to be {v2} before the move, got {before['VersionId']}"
    )

    # Move AWSCURRENT back from v2 to v1.
    sm.update_secret_version_stage(
        SecretId=name,
        VersionStage="AWSCURRENT",
        MoveToVersionId=v1,
        RemoveFromVersionId=v2,
    )

    current = sm.get_secret_value(SecretId=name)
    assert current["VersionId"] == v1, (
        f"expected AWSCURRENT to be {v1} after the move, got {current['VersionId']}"
    )
    assert current["SecretString"] == "v1", (
        f"expected AWSCURRENT value 'v1', got {current['SecretString']!r}"
    )

    previous = sm.get_secret_value(SecretId=name, VersionStage="AWSPREVIOUS")
    assert previous["VersionId"] == v2, (
        f"expected AWSPREVIOUS to be {v2} after the move, got {previous['VersionId']}"
    )
    assert previous["SecretString"] == "v2", (
        f"expected AWSPREVIOUS value 'v2', got {previous['SecretString']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
