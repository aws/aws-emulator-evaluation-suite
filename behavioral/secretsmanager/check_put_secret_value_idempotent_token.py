"""put-secret-value-idempotent-token."""
from __future__ import annotations

import uuid

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

CHECK = "put-secret-value-idempotent-token"
GROUP = 'state-machine'
SERVICES = ['secretsmanager']

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutSecretValue retried with the same ClientRequestToken+content is idempotent (no new version)."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-secret-")
    _create_secret(
        sm, ctx, name=name, secret_string="v1",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )

    token = uuid.uuid4().hex
    first = sm.put_secret_value(
        SecretId=name, SecretString="v2", ClientRequestToken=token
    )
    second = sm.put_secret_value(
        SecretId=name, SecretString="v2", ClientRequestToken=token
    )
    assert second["VersionId"] == first["VersionId"], (
        "identical retry with same token/content must not mint a new version"
    )

    versions = sm.list_secret_version_ids(SecretId=name)["Versions"]
    version_ids = {v["VersionId"] for v in versions}
    assert first["VersionId"] in version_ids, (
        f"the version minted by the put must be independently readable via "
        f"list_secret_version_ids: {first['VersionId']!r} not in {sorted(version_ids)!r}"
    )
    # exactly 2 distinct versions total: the initial create + the single put
    assert len(version_ids) == 2, f"expected 2 versions, found {len(version_ids)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
