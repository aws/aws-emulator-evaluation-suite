"""restore-secret-clears-deletion."""
from __future__ import annotations

import time

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

CHECK = "restore-secret-clears-deletion"
GROUP = 'state-machine'
SERVICES = ['secretsmanager']

@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """RestoreSecret reverses a pending deletion and makes the secret accessible again."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-secret-")
    _create_secret(sm, ctx, name=name, secret_string="restorable")
    sm.delete_secret(SecretId=name, RecoveryWindowInDays=7)

    # Positive control: the secret must actually be pending deletion before restore can be
    # credited with reversing it — otherwise a target where delete_secret is a no-op passes too.
    pending = sm.describe_secret(SecretId=name)
    assert pending.get("DeletedDate") is not None, (
        f"expected DeletedDate set after DeleteSecret, got {pending.get('DeletedDate')!r}"
    )

    sm.restore_secret(SecretId=name)

    # DescribeSecret's view of DeletedDate can lag RestoreSecret by a beat, so this is a
    # bounded retry on genuine propagation delay, not an assumed-immediate read.
    desc = _poll_until_restored(sm, name, timeout_s=30.0)
    assert "DeletedDate" not in desc or desc.get("DeletedDate") is None, (
        f"expected DeletedDate cleared after RestoreSecret, got {desc.get('DeletedDate')!r}"
    )

    val = sm.get_secret_value(SecretId=name)
    assert val["SecretString"] == "restorable", (
        f"expected SecretString 'restorable' to survive delete/restore, got {val['SecretString']!r}"
    )


def _poll_until_restored(sm, name, timeout_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sm.describe_secret(SecretId=name)
        if "DeletedDate" not in last or last.get("DeletedDate") is None:
            return last
        time.sleep(2)
    raise AssertionError(
        f"DeletedDate still set {timeout_s}s after RestoreSecret: {last.get('DeletedDate')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
