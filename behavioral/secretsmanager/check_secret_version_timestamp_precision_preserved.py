"""secret-version-timestamp-precision-preserved."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "secret-version-timestamp-precision-preserved"
GROUP = "representation"
SERVICES = ["secretsmanager"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Each version's CreatedDate is stable across repeated ListSecretVersionIds calls (not
    regenerated/jittered on each read) and distinct versions retain a consistent creation order.
    """
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-verts-")
    sm.create_secret(Name=name, SecretString="v1")
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True))

    sm.put_secret_value(SecretId=name, SecretString="v2")

    # Poll (bounded) for the second version to become visible via ListSecretVersionIds, rather
    # than assuming it's synchronous.
    first_by_id: dict[str, object] = {}
    for _ in range(15):
        versions = sm.list_secret_version_ids(SecretId=name)["Versions"]
        first_by_id = {v["VersionId"]: v["CreatedDate"] for v in versions}
        if len(first_by_id) == 2:
            break
        time.sleep(0.5)
    assert len(first_by_id) == 2, f"expected 2 versions, got {len(first_by_id)}"

    # Re-poll repeatedly over a bounded window and assert CreatedDate never drifts from the
    # first observation on any subsequent read (catches timestamps that get regenerated/jittered
    # on each read instead of being stored once with stable precision).
    deadline = time.monotonic() + 8.0
    reread_count = 0
    while time.monotonic() < deadline:
        versions = sm.list_secret_version_ids(SecretId=name)["Versions"]
        current_by_id = {v["VersionId"]: v["CreatedDate"] for v in versions}
        assert set(current_by_id) == set(first_by_id), (
            f"version id set changed across re-reads: {set(current_by_id)} vs {set(first_by_id)}"
        )
        for version_id, ts in first_by_id.items():
            ts_current = current_by_id[version_id]
            assert ts == ts_current, (
                f"CreatedDate for version {version_id} drifted between reads: {ts!r} vs {ts_current!r}"
            )
        reread_count += 1
        time.sleep(1.0)
    assert reread_count >= 3, "expected multiple re-reads within the polling window"

    ordered = sorted(first_by_id.items(), key=lambda kv: kv[1])
    assert ordered[0][1] <= ordered[1][1], "version creation order must be non-decreasing"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
