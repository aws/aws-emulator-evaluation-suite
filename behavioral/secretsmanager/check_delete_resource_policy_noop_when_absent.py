"""delete-resource-policy-noop-when-absent."""
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
    params = {"Name": name, "Tags": [{"Key": "sim2real-owner", "Value": "behavioral-check"}]}
    if secret_string is not None:
        params["SecretString"] = secret_string
    params.update(kwargs)
    resp = sm.create_secret(**params)
    ctx.on_cleanup(lambda: _force_delete(sm, name))
    return resp

CHECK = "delete-resource-policy-noop-when-absent"
GROUP = 'error-semantics'
SERVICES = ['secretsmanager']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteResourcePolicy on a secret with no policy is a no-op success, not an error."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-secret-")
    _create_secret(sm, ctx, name=name)

    # Independent read, through GetResourcePolicy, of the pre-delete state.
    before = sm.get_resource_policy(SecretId=name)
    assert not before.get("ResourcePolicy"), (
        f"expected no ResourcePolicy on a fresh secret, got {before.get('ResourcePolicy')!r}"
    )

    # Should not raise even though no policy was ever attached.
    resp = sm.delete_resource_policy(SecretId=name)
    assert resp.get("Name") == name, f"expected DeleteResourcePolicy Name {name!r}, got {resp.get('Name')!r}"

    # Terminal assertion: an independent read, through a different operation
    # (GetResourcePolicy) than the one that mutated, showing the no-op left
    # state unchanged rather than merely that the mutating call didn't raise.
    after = sm.get_resource_policy(SecretId=name)
    assert not after.get("ResourcePolicy"), (
        f"expected no ResourcePolicy after a no-op delete, got {after.get('ResourcePolicy')!r}"
    )
    assert after.get("Name") == name, f"expected GetResourcePolicy Name {name!r}, got {after.get('Name')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
