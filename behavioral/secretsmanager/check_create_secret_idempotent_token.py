"""create-secret-idempotent-token."""
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

CHECK = "create-secret-idempotent-token"
GROUP = 'state-machine'
SERVICES = ['secretsmanager']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSecret with the same ClientRequestToken and identical content is idempotent."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-secret-")
    token = str(uuid.uuid4())
    resp1 = _create_secret(sm, ctx, name=name, secret_string="same-value", ClientRequestToken=token)
    resp2 = sm.create_secret(Name=name, SecretString="same-value", ClientRequestToken=token)
    assert resp1["VersionId"] == resp2["VersionId"], (
        f"a byte-identical replay of the same ClientRequestToken must return the same version: "
        f"{resp1['VersionId']!r} != {resp2['VersionId']!r}"
    )
    assert resp1["ARN"] == resp2["ARN"], (
        f"a byte-identical replay of the same ClientRequestToken must return the same secret: "
        f"{resp1['ARN']!r} != {resp2['ARN']!r}"
    )

    # Independent read at the destination, through a different operation than the mutating
    # CreateSecret calls above: the replay must not have minted a second version, and the
    # stored material must be exactly what was requested.
    arn = resp1["ARN"]
    current = sm.get_secret_value(SecretId=arn)
    assert current["VersionId"] == resp1["VersionId"], (
        f"AWSCURRENT must still point at the version CreateSecret returned: "
        f"{current['VersionId']!r} != {resp1['VersionId']!r}"
    )
    assert current["SecretString"] == "same-value", (
        f"the stored secret material must be exactly what was created: got {current['SecretString']!r}"
    )
    version_ids = {v["VersionId"] for v in sm.list_secret_version_ids(SecretId=arn)["Versions"]}
    assert version_ids == {resp1["VersionId"]}, (
        f"an idempotent replay must not mint a second version, saw {sorted(version_ids)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
