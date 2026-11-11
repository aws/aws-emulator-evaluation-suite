"""list-secret-version-ids-includes-versions."""
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

CHECK = "list-secret-version-ids-includes-versions"
GROUP = 'state-machine'
SERVICES = ['secretsmanager']

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListSecretVersionIds reflects every version created via PutSecretValue."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-secret-")
    create_resp = _create_secret(sm, ctx, name=name, secret_string="v1")
    v1 = create_resp["VersionId"]
    put_resp = sm.put_secret_value(SecretId=name, SecretString="v2")
    v2 = put_resp["VersionId"]

    listed = sm.list_secret_version_ids(SecretId=name)
    version_ids = {v["VersionId"] for v in listed["Versions"]}
    assert version_ids == {v1, v2}, (
        f"ListSecretVersionIds returned {version_ids!r}, expected exactly the two "
        f"created versions {{{v1!r}, {v2!r}}}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
