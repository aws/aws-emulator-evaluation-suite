"""update-security-requirement-pack-persists-changes."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-security-requirement-pack-persists-changes"
GROUP = "state"
SERVICES = ["securityagent"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateSecurityRequirementPack changes to name/description/status are durable and
    visible on a subsequent Get."""
    sa = ctx.client("securityagent")
    name = ctx.unique_name("sim2real-behav-pack-")
    pack_id = sa.create_security_requirement_pack(
        name=name,
        description="before",
        tags={"sim2real": "update-security-requirement-pack-persists-changes"},
    )["packId"]

    new_name = ctx.unique_name("sim2real-behav-pack-renamed-")

    def _cleanup():
        sa.delete_security_requirement_pack(packId=pack_id)

    ctx.on_cleanup(_cleanup)

    sa.update_security_requirement_pack(
        packId=pack_id, name=new_name, description="after", status="DISABLED"
    )

    got = sa.get_security_requirement_pack(packId=pack_id)
    assert got["name"] == new_name, f"expected name={new_name!r}, got {got['name']!r}"
    assert got["description"] == "after", f"expected description='after', got {got['description']!r}"
    assert got["status"] == "DISABLED", f"expected status=DISABLED, got {got['status']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
