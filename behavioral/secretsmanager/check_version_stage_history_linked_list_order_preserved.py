"""version-stage-history-linked-list-order-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "version-stage-history-linked-list-order-preserved"
GROUP = "ordering"
SERVICES = ["secretsmanager"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """After a chain of PutSecretValue calls, each version's predecessor/AWSPREVIOUS linkage
    matches the true chronological write order, not just the two most recent."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-prevlink-")

    create_resp = sm.create_secret(Name=name, SecretString="v0")
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True))

    chain = [("v0", create_resp["VersionId"])]

    for i in range(1, 5):
        value = f"v{i}"
        resp = sm.put_secret_value(SecretId=name, SecretString=value)
        new_version_id = resp["VersionId"]

        # Immediately after each write, AWSCURRENT must be *this* version and AWSPREVIOUS must
        # be the version that was current one step ago -- not v0, and not stale from two steps
        # back -- which is exactly the bug a fixed-depth "last two" linked list would exhibit.
        expected_previous_label, expected_previous_id = chain[-1]

        current = sm.get_secret_value(SecretId=name, VersionStage="AWSCURRENT")
        assert current["SecretString"] == value, (
            f"AWSCURRENT should be {value!r} right after writing it, got {current['SecretString']!r}"
        )
        assert current["VersionId"] == new_version_id, (
            f"AWSCURRENT VersionId should be the version just written ({new_version_id}), "
            f"got {current['VersionId']}"
        )

        previous = sm.get_secret_value(SecretId=name, VersionStage="AWSPREVIOUS")
        assert previous["VersionId"] == expected_previous_id, (
            f"AWSPREVIOUS after writing {value!r} points at version {previous['VersionId']} "
            f"but the true predecessor is {expected_previous_label!r} ({expected_previous_id})"
        )
        assert previous["SecretString"] == expected_previous_label, (
            f"AWSPREVIOUS content is {previous['SecretString']!r}, expected the immediately "
            f"prior write {expected_previous_label!r}"
        )

        chain.append((value, new_version_id))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
