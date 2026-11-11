"""create-secret-active-state."""
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

CHECK = "create-secret-active-state"
GROUP = 'state-machine'
SERVICES = ['secretsmanager']

@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """CreateSecret produces an immediately-active secret with an AWSCURRENT version."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-secret-")
    resp = _create_secret(sm, ctx, name=name, secret_string="hello-world")
    assert resp["Name"] == name, f"expected CreateSecret to echo Name {name!r}, got {resp.get('Name')!r}"
    assert "ARN" in resp and resp["ARN"], f"expected CreateSecret to return a non-empty ARN, got {resp.get('ARN')!r}"

    desc = sm.describe_secret(SecretId=name)
    assert desc["Name"] == name, f"expected DescribeSecret to report Name {name!r}, got {desc.get('Name')!r}"
    assert "DeletedDate" not in desc, f"expected an active secret to have no DeletedDate, got {desc.get('DeletedDate')!r}"

    val = sm.get_secret_value(SecretId=name)
    assert val["SecretString"] == "hello-world", f"expected SecretString 'hello-world', got {val.get('SecretString')!r}"
    assert "AWSCURRENT" in val["VersionStages"], f"expected AWSCURRENT in VersionStages, got {val.get('VersionStages')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
