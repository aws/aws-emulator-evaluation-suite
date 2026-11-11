"""update-secret-creates-new-current-version."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-secret-creates-new-current-version"
GROUP = "state-machine"
SERVICES = ["secretsmanager"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateSecret with new SecretString mints a new AWSCURRENT and demotes the old to AWSPREVIOUS."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-sm-update-")
    created = sm.create_secret(
        Name=name,
        SecretString="v1",
        Description="original",
        Tags=[
            {"Key": "sim2real", "Value": "update-secret-creates-new-current-version"},
            {"Key": "sim2real:managed", "Value": "true"},
        ],
    )
    ctx.on_cleanup(lambda: _force_delete_secret(sm, created["ARN"]))
    v1 = created["VersionId"]

    updated = sm.update_secret(SecretId=name, SecretString="v2")
    v2 = updated["VersionId"]
    assert v2 != v1, "changing the secret value must mint a new version"

    desc = sm.describe_secret(SecretId=name)
    stages = desc["VersionIdsToStages"]
    assert "AWSCURRENT" in stages[v2], f"new version {v2} must carry AWSCURRENT, stages={stages}"
    assert "AWSPREVIOUS" in stages.get(v1, []), "prior AWSCURRENT must be demoted to AWSPREVIOUS"
    got = sm.get_secret_value(SecretId=name)["SecretString"]
    assert got == "v2", f"expected the current value to be v2, got {got!r}"

    # metadata-only update must NOT create a new version
    sm.update_secret(SecretId=name, Description="rewritten")
    desc2 = _poll_until(
        lambda: sm.describe_secret(SecretId=name),
        lambda d: d.get("Description") == "rewritten",
        timeout_s=60,
        interval_s=2,
        description="description-only update becomes visible",
    )
    assert desc2["Description"] == "rewritten", (
        f"expected Description to be 'rewritten', got {desc2['Description']!r}"
    )
    version_ids = {
        v["VersionId"] for v in sm.list_secret_version_ids(SecretId=name)["Versions"]
    }
    assert version_ids == {v1, v2}, (
        f"a description-only UpdateSecret must not mint a version, found {version_ids}"
    )
    current = sm.get_secret_value(SecretId=name)
    assert current["VersionId"] == v2 and current["SecretString"] == "v2", (
        f"expected current version {v2!r} with value 'v2', "
        f"got version {current['VersionId']!r} with value {current['SecretString']!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _force_delete_secret(sm, secret_id: str) -> None:
    """Force-delete without a recovery window; an already-pending-deletion secret is
    restored first so the force delete can land."""
    try:
        sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
    except Exception:
        try:
            sm.restore_secret(SecretId=secret_id)
            sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
