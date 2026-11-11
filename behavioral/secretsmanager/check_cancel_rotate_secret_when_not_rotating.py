"""cancel-rotate-secret-when-not-rotating."""
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

CHECK = "cancel-rotate-secret-when-not-rotating"
GROUP = 'state-machine'
SERVICES = ['secretsmanager']

@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """CancelRotateSecret on a secret with no rotation in progress is a tolerated no-op.

    Real AWS accepts the call and simply leaves rotation disabled -- it does NOT
    raise, and it must not enable rotation or disturb the version staging.
    """
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-secret-")
    created = _create_secret(
        sm, ctx, name=name, secret_string="value",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    v1 = created["VersionId"]

    resp = sm.cancel_rotate_secret(SecretId=name)
    assert resp["ARN"] == created["ARN"], (
        f"expected CancelRotateSecret to echo the created ARN {created['ARN']!r}, got {resp.get('ARN')!r}"
    )
    assert resp["Name"] == name, (
        f"expected CancelRotateSecret to echo Name {name!r}, got {resp.get('Name')!r}"
    )

    desc = sm.describe_secret(SecretId=name)
    assert not desc.get("RotationEnabled", False), (
        "CancelRotateSecret must never turn rotation ON"
    )
    assert "AWSCURRENT" in desc["VersionIdsToStages"][v1], (
        "cancelling a non-existent rotation must not disturb version staging"
    )
    value = sm.get_secret_value(SecretId=name)["SecretString"]
    assert value == "value", (
        f"cancelling a non-existent rotation must not disturb the secret value, expected 'value' got {value!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
