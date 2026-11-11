"""put-secret-value-new-current-version."""
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
    params = {"Name": name, "Tags": [{"Key": "sim2real-check", "Value": CHECK}]}
    if secret_string is not None:
        params["SecretString"] = secret_string
    params.update(kwargs)
    resp = sm.create_secret(**params)
    ctx.on_cleanup(lambda: _force_delete(sm, name))
    return resp

CHECK = "put-secret-value-new-current-version"
GROUP = 'state-machine'
SERVICES = ['secretsmanager']

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutSecretValue creates a new AWSCURRENT version and demotes the old one to AWSPREVIOUS."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-secret-")
    create_resp = _create_secret(sm, ctx, name=name, secret_string="v1")
    old_version_id = create_resp["VersionId"]

    put_resp = sm.put_secret_value(SecretId=name, SecretString="v2")
    new_version_id = put_resp["VersionId"]
    assert new_version_id != old_version_id, (
        f"PutSecretValue must mint a new version id, got the same id {new_version_id} as the "
        "original AWSCURRENT version"
    )

    val = sm.get_secret_value(SecretId=name)
    assert val["SecretString"] == "v2", (
        f"default GetSecretValue must resolve the new AWSCURRENT value 'v2', got {val['SecretString']!r}"
    )
    assert val["VersionId"] == new_version_id, (
        f"default GetSecretValue must resolve version {new_version_id}, got {val['VersionId']}"
    )

    old_val = sm.get_secret_value(SecretId=name, VersionId=old_version_id)
    assert "AWSPREVIOUS" in old_val["VersionStages"], (
        f"the demoted version {old_version_id} must carry AWSPREVIOUS, got {old_val['VersionStages']}"
    )
    assert "AWSCURRENT" not in old_val["VersionStages"], (
        f"the demoted version {old_version_id} must not still carry AWSCURRENT, got "
        f"{old_val['VersionStages']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
