"""list-secrets-filter-and-planned-deletion."""
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

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=2):
    """Poll probe() until predicate() holds; return the last result (raises nothing on timeout)."""
    import time
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            return last
        time.sleep(interval_s)
        last = probe()
    return last

CHECK = "list-secrets-filter-and-planned-deletion"
GROUP = 'state-machine'
SERVICES = ['secretsmanager']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListSecrets name-filters, and hides pending-deletion secrets unless IncludePlannedDeletion."""
    sm = ctx.client("secretsmanager")
    prefix = ctx.unique_name("sim2real-behav-list-")
    name_a = f"{prefix}-a"
    name_b = f"{prefix}-b"
    tags = [{"Key": "sim2real", "Value": CHECK}]
    _create_secret(sm, ctx, name=name_a, secret_string="a", Tags=tags)
    _create_secret(sm, ctx, name=name_b, secret_string="b", Tags=tags)

    # ListSecrets is eventually consistent; every target gets the same bounded wait.
    timeout_s = 60

    def listed(**kwargs) -> set:
        resp = sm.list_secrets(
            Filters=[{"Key": "name", "Values": [prefix]}], **kwargs
        )
        return {s["Name"] for s in resp.get("SecretList", [])}

    both = _poll_until(
        lambda: listed(),
        lambda names: {name_a, name_b} <= names,
        timeout_s=timeout_s,
    )
    assert both == {name_a, name_b}, f"name filter must return exactly the prefixed secrets, got {both}"

    sm.delete_secret(SecretId=name_b, RecoveryWindowInDays=7)

    remaining = _poll_until(
        lambda: listed(),
        lambda names: name_b not in names,
        timeout_s=timeout_s,
    )
    assert name_a in remaining, "the active secret must still be listed"
    assert name_b not in remaining, "a secret pending deletion must be hidden from ListSecrets by default"

    with_deleted = _poll_until(
        lambda: listed(IncludePlannedDeletion=True),
        lambda names: name_b in names,
        timeout_s=timeout_s,
    )
    assert {name_a, name_b} <= with_deleted, (
        "IncludePlannedDeletion=True must surface the pending-deletion secret"
    )

    sm.restore_secret(SecretId=name_b)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
