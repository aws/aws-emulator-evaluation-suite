"""inventory-schema-and-instance-views."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "inventory-schema-and-instance-views"
GROUP = 'state-machine'
SERVICES = ['ssm']

@tags("axis:happy-path", "cap:c1", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetInventorySchema exposes AWS:InstanceInformation with InstanceId, and the inventory,
    instance-information and patch-state reads return empty lists for a nonexistent instance."""

    ssm = ctx.client("ssm")
    # Emptiness is scoped to a fabricated id; the account may hold other real managed nodes.
    bogus_id = "i-0123456789abcdef0"

    schemas = ssm.get_inventory_schema()["Schemas"]
    type_names = {s["TypeName"] for s in schemas}
    assert "AWS:InstanceInformation" in type_names, sorted(type_names)
    instance_schema = next(
        s for s in schemas if s["TypeName"] == "AWS:InstanceInformation"
    )
    attr_names = {a["Name"] for a in instance_schema["Attributes"]}
    assert "InstanceId" in attr_names, sorted(attr_names)

    inventory = ssm.get_inventory(
        Filters=[
            {
                "Key": "AWS:InstanceInformation.InstanceId",
                "Values": [bogus_id],
                "Type": "Equal",
            }
        ]
    )["Entities"]
    assert inventory == [], f"expected no inventory entities for {bogus_id}, got {inventory}"

    info = ssm.describe_instance_information(
        Filters=[{"Key": "InstanceIds", "Values": [bogus_id]}]
    )["InstanceInformationList"]
    assert info == [], f"expected no instance info for {bogus_id}, got {info}"

    states = ssm.describe_instance_patch_states(InstanceIds=[bogus_id])[
        "InstancePatchStates"
    ]
    assert states == [], f"expected no patch states for {bogus_id}, got {states}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
