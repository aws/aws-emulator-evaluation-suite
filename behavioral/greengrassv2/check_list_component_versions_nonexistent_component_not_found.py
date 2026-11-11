"""list-component-versions-nonexistent-component-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-component-versions-nonexistent-component-not-found"
GROUP = "state"
SERVICES = ["greengrassv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListComponentVersions for a never-created component ARN returns an empty componentVersions
    list and no nextToken, not ResourceNotFoundException.
    """
    gg = ctx.client("greengrassv2")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-ggv2-missing-")
    component_arn = f"arn:aws:greengrass:{ctx.region}:{account_id}:components:{name}"
    resp = gg.list_component_versions(arn=component_arn)
    assert resp["componentVersions"] == [], (
        f"expected an empty componentVersions page for a never-created component, "
        f"got {resp['componentVersions']!r}"
    )
    assert resp.get("nextToken") is None, (
        f"expected no nextToken on an empty page, got {resp.get('nextToken')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
