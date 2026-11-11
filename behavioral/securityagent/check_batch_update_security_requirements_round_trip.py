"""batch-update-security-requirements-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-update-security-requirements-round-trip"
GROUP = "data-plane"
SERVICES = ["securityagent"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchUpdateSecurityRequirements mutates fields on an existing requirement and the
    change is visible via BatchGetSecurityRequirements; the immutable name is unchanged."""
    sa = ctx.client("securityagent")
    pack_id = sa.create_security_requirement_pack(name=ctx.unique_name("sim2real-behav-pack-"))["packId"]
    ctx.on_cleanup(lambda: sa.delete_security_requirement_pack(packId=pack_id))

    req_name = ctx.unique_name("sim2real-behav-req-")
    sa.batch_create_security_requirements(
        packId=pack_id,
        securityRequirements=[
            {"name": req_name, "description": "original-desc", "domain": "iam", "evaluation": "original-eval"}
        ],
    )
    ctx.on_cleanup(lambda: sa.batch_delete_security_requirements(packId=pack_id, securityRequirementNames=[req_name]))

    result = sa.batch_update_security_requirements(
        packId=pack_id,
        securityRequirements=[{"name": req_name, "description": "updated-desc"}],
    )
    assert result["errors"] == [], result["errors"]
    assert req_name in result["updatedSecurityRequirementNames"], result["updatedSecurityRequirementNames"]

    got = sa.batch_get_security_requirements(packId=pack_id, securityRequirementNames=[req_name])
    entry = got["securityRequirements"][0]
    assert entry["name"] == req_name, entry
    assert entry["description"] == "updated-desc", entry["description"]
    # untouched fields survive a partial update unchanged
    assert entry["domain"] == "iam", entry["domain"]
    assert entry["evaluation"] == "original-eval", entry["evaluation"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
