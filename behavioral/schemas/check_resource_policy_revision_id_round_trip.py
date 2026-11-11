"""resource-policy-revision-id-round-trip."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "resource-policy-revision-id-round-trip"
GROUP = "state"
SERVICES = ["schemas"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy produces a fresh RevisionId each successful update and GetResourcePolicy reflects it."""
    schemas = ctx.client("schemas")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    region = schemas.meta.region_name

    registry = ctx.unique_name("sim2real-schemas-reg-")
    schemas.create_registry(RegistryName=registry, Tags={"sim2real": "true"})
    ctx.on_cleanup(lambda: schemas.delete_registry(RegistryName=registry))

    policy_v1 = _policy_doc(account_id, region, registry, ["schemas:DescribeSchema"])
    put1 = schemas.put_resource_policy(RegistryName=registry, Policy=json.dumps(policy_v1))
    ctx.on_cleanup(lambda: schemas.delete_resource_policy(RegistryName=registry))
    revision1 = put1["RevisionId"]

    fetched = schemas.get_resource_policy(RegistryName=registry)
    assert fetched["RevisionId"] == revision1, (
        f"GetResourcePolicy revision {fetched['RevisionId']!r} != PutResourcePolicy revision {revision1!r}"
    )
    sid1 = json.loads(fetched["Policy"])["Statement"][0]["Sid"]
    assert sid1 == "AllowDescribe", f"expected Sid 'AllowDescribe', GetResourcePolicy returned {sid1!r}"

    policy_v2 = _policy_doc(account_id, region, registry, ["schemas:DescribeSchema", "schemas:ListSchemas"])
    put2 = schemas.put_resource_policy(
        RegistryName=registry, Policy=json.dumps(policy_v2), RevisionId=revision1
    )
    revision2 = put2["RevisionId"]
    assert revision2 != revision1, f"second PutResourcePolicy reused stale revision {revision1!r}"

    fetched2 = schemas.get_resource_policy(RegistryName=registry)
    assert fetched2["RevisionId"] == revision2, (
        f"GetResourcePolicy revision {fetched2['RevisionId']!r} != second PutResourcePolicy revision {revision2!r}"
    )
    actions2 = set(json.loads(fetched2["Policy"])["Statement"][0]["Action"])
    expected2 = {"schemas:DescribeSchema", "schemas:ListSchemas"}
    assert actions2 == expected2, f"expected actions {expected2}, GetResourcePolicy returned {actions2}"


def _policy_doc(account_id: str, region: str, registry_name: str, actions: list[str]) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowDescribe",
                "Effect": "Allow",
                "Principal": {"AWS": [account_id]},
                "Action": actions,
                "Resource": [
                    f"arn:aws:schemas:{region}:{account_id}:registry/{registry_name}",
                    f"arn:aws:schemas:{region}:{account_id}:schema/{registry_name}*",
                ],
            }
        ],
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
