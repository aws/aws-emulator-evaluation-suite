"""list-secret-version-ids-descending-creation-order."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "list-secret-version-ids-descending-creation-order"
GROUP = "ordering"
SERVICES = ["secretsmanager"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListSecretVersionIds returns every version with a CreatedDate that reproduces the true write
    order when sorted, and the most recently created version carries AWSCURRENT."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-versionorder-")
    created = sm.create_secret(
        Name=name,
        SecretString="v0",
        Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
    )
    arn = created["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True))

    created_ids = [created["VersionId"]]
    for i in range(1, 4):
        time.sleep(1.5)  # keep CreatedDate values distinguishable
        token = str(uuid.uuid4())
        sm.put_secret_value(SecretId=arn, ClientRequestToken=token, SecretString=f"v{i}")
        created_ids.append(token)

    versions = sm.list_secret_version_ids(SecretId=arn, IncludeDeprecated=True)["Versions"]
    assert {v["VersionId"] for v in versions} == set(created_ids), (
        f"ListSecretVersionIds did not return all created versions: "
        f"{[v['VersionId'] for v in versions]} vs {created_ids}"
    )

    by_id = {v["VersionId"]: v for v in versions}
    dates_in_creation_order = [by_id[vid]["CreatedDate"] for vid in created_ids]
    assert dates_in_creation_order == sorted(dates_in_creation_order), (
        "CreatedDate values do not increase monotonically in actual creation order: "
        f"{dates_in_creation_order}"
    )

    # The raw array order is not documented, so only the CreatedDate ordering is asserted.
    sorted_desc = sorted(versions, key=lambda v: v["CreatedDate"], reverse=True)
    assert [v["VersionId"] for v in sorted_desc] == list(reversed(created_ids)), (
        "sorting versions by CreatedDate descending did not reproduce true creation "
        "chronology in reverse"
    )

    most_recent = sorted_desc[0]
    assert most_recent["VersionId"] == created_ids[-1], (
        f"the most-recently-created version by CreatedDate was {most_recent['VersionId']!r}, "
        f"expected the last version written {created_ids[-1]!r}"
    )
    assert "AWSCURRENT" in most_recent.get("VersionStages", []), (
        f"expected AWSCURRENT on the most-recently-created version {most_recent['VersionId']!r}, "
        f"got stages {most_recent.get('VersionStages', [])}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
