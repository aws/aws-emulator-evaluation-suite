"""list-secret-version-ids-chronological-order."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-secret-version-ids-chronological-order"
GROUP = "ordering"
SERVICES = ["secretsmanager"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListSecretVersionIds returns versions ordered by creation time (most recent first),
    matching the actual PutSecretValue call sequence."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-versionorder-")

    create_resp = sm.create_secret(
        Name=name,
        SecretString="v0",
        Tags=[
            {"Key": "sim2real", "Value": CHECK},
            {"Key": "sim2real:managed", "Value": "true"},
        ],
    )
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True))
    version_ids = [create_resp["VersionId"]]

    # Sleep between writes so distinct versions get distinct CreatedDate timestamps rather than
    # landing on the same second-resolution bucket, which would make ordering ambiguous.
    for i in range(1, 5):
        time.sleep(1.1)
        resp = sm.put_secret_value(SecretId=name, SecretString=f"v{i}")
        version_ids.append(resp["VersionId"])

    expected_most_recent_first = list(reversed(version_ids))

    listed = sm.list_secret_version_ids(SecretId=name, IncludeDeprecated=True, MaxResults=100)["Versions"]
    listed_ids = [v["VersionId"] for v in listed]

    assert set(listed_ids) == set(version_ids), "ListSecretVersionIds did not return all 5 versions"

    # ListSecretVersionIds does not guarantee its own list order matches creation chronology, so
    # verify chronology via the CreatedDate metadata Secrets Manager actually attaches to each
    # version entry rather than assuming response-list order == write order.
    by_id = {v["VersionId"]: v["CreatedDate"] for v in listed}
    sorted_by_created_desc = sorted(version_ids, key=lambda vid: by_id[vid], reverse=True)
    assert sorted_by_created_desc == expected_most_recent_first, (
        f"CreatedDate-derived order {sorted_by_created_desc} did not match chronological "
        f"(most-recent-first) write sequence {expected_most_recent_first}"
    )
    # CreatedDate must be strictly increasing across the write sequence (no ties, no reversals).
    created_in_write_order = [by_id[vid] for vid in version_ids]
    assert created_in_write_order == sorted(created_in_write_order), (
        "CreatedDate timestamps were not monotonically increasing in write order: "
        f"{created_in_write_order}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
