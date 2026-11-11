"""update-secret-version-stage-remove-current-without-move-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return the botocore error (code, message) if a ClientError was raised, else raise."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")

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

CHECK = "update-secret-version-stage-remove-current-without-move-fails"
GROUP = 'overly-permissive'
SERVICES = ['secretsmanager']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Removing AWSCURRENT without a MoveToVersionId is rejected (must always have exactly one AWSCURRENT)."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-secret-")
    created = _create_secret(sm, ctx, name=name, secret_string="v1")
    v1 = created["VersionId"]

    # positive control: a legitimate move (RemoveFromVersionId paired with a
    # MoveToVersionId) succeeds, proving the target does not simply reject every
    # UpdateSecretVersionStage call for this secret.
    put_resp = sm.put_secret_value(SecretId=name, SecretString="v2", VersionStages=["AWSPENDING"])
    v2 = put_resp["VersionId"]
    sm.update_secret_version_stage(
        SecretId=name, VersionStage="AWSCURRENT", MoveToVersionId=v2, RemoveFromVersionId=v1
    )
    current = sm.get_secret_value(SecretId=name)
    assert current["VersionId"] == v2, (
        f"positive control failed: expected AWSCURRENT moved to {v2}, got {current['VersionId']}"
    )

    code, message = _error(
        lambda: sm.update_secret_version_stage(
            SecretId=name, VersionStage="AWSCURRENT", RemoveFromVersionId=v2
        )
    )
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException removing sole AWSCURRENT without a move target, got {code}"
    )
    expected = (
        "You can only move staging label AWSCURRENT to a different secret version. "
        "It can't be completely removed."
    )
    assert message == expected, f"rejection message {message!r}, expected {expected!r}"

    # effect absent: an independent read (get_secret_value, a different operation
    # than the rejected update_secret_version_stage call) shows AWSCURRENT unmoved
    current = sm.get_secret_value(SecretId=name)
    assert current["VersionId"] == v2, (
        f"AWSCURRENT moved despite the rejected call, now on {current['VersionId']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
