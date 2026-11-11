"""list-instance-types-returns-supported-types."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-instance-types-returns-supported-types"
GROUP = "control-plane"
SERVICES = ["workspaces-instances"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListInstanceTypes returns a non-empty catalog of instance types, each with a
    well-formed InstanceType string and at least one supported configuration entry."""
    wsi = ctx.client("workspaces-instances")

    resp = wsi.list_instance_types()
    instance_types = resp["InstanceTypes"]
    assert len(instance_types) > 0

    sample = instance_types[0]
    assert "." in sample["InstanceType"]
    configs = sample["SupportedInstanceConfigurations"]
    assert len(configs) > 0, "expected at least one supported configuration entry"

    type_names = {it["InstanceType"] for it in instance_types}
    assert len(type_names) == len(instance_types), "duplicate InstanceType entries returned"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
