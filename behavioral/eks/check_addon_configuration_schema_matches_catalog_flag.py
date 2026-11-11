"""addon-configuration-schema-matches-catalog-flag."""
from __future__ import annotations

import json

from behavioral_harness import tags


CHECK = "addon-configuration-schema-matches-catalog-flag"
GROUP = 'metadata'
SERVICES = ['eks']

# Most add-ons (vpc-cni among them) have requiresConfiguration False for every
# version, so they can never exercise the "flagged => real schema" assertion below.
# The add-on is the first one in the live catalogue with a flagged version, so the
# flag is actually put to the test whatever the catalogue holds.

@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAddonConfiguration returns a JSON Schema whose shape agrees with the catalogue's requiresConfiguration flag for that exact add-on version."""
    c = ctx.client("eks")
    addon = None
    for page in c.get_paginator("describe_addon_versions").paginate():
        addon = next(
            (a for a in page["addons"]
             if any(v.get("requiresConfiguration") for v in a["addonVersions"])),
            None,
        )
        if addon is not None:
            break
    assert addon is not None, "no catalogue add-on has a version flagged requiresConfiguration"
    addon_name = addon["addonName"]
    # Flagged versions first (stable sort), so the checked slice holds at least one.
    versions = sorted(addon["addonVersions"], key=lambda v: not v.get("requiresConfiguration"))

    checked = 0
    saw_required_configuration = False
    for info in versions[:3]:
        version = info["addonVersion"]
        cfg = c.describe_addon_configuration(
            addonName=addon_name, addonVersion=version
        )
        assert cfg["addonName"] == addon_name, cfg
        assert cfg["addonVersion"] == version, cfg

        schema = json.loads(cfg["configurationSchema"])
        assert isinstance(schema, dict), schema
        # A version the catalogue says is configurable must expose properties.
        if info.get("requiresConfiguration"):
            saw_required_configuration = True
            assert schema.get("properties") or schema.get("$ref"), (
                f"{version} is flagged requiresConfiguration but the schema is bare: {schema}"
            )
        checked += 1

    assert checked == min(3, len(versions)), checked
    # Without this, the branch above can silently never fire (as it never did for
    # vpc-cni) and the check passes having verified nothing.
    assert saw_required_configuration, (
        f"none of the checked {addon_name} versions were flagged requiresConfiguration; "
        "the schema-shape assertion above never ran"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
