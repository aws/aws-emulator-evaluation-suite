"""batch-create-security-requirements-duplicate-partial-failure."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-create-security-requirements-duplicate-partial-failure"
GROUP = "error-semantics"
SERVICES = ["securityagent"]


@tags("axis:happy-path", "cap:c1", "plane:control")
def run(ctx) -> None:
    """BatchCreateSecurityRequirements mixing a duplicate name with a new one is all-or-nothing: the
    duplicate reports ConflictException, the new entry NotProcessed and is not created, and the
    existing requirement keeps its original description."""
    sa = ctx.client("securityagent")
    pack_id = sa.create_security_requirement_pack(
        name=ctx.unique_name("sim2real-behav-pack-"), tags={"sim2real": "behavioral"}
    )["packId"]
    ctx.on_cleanup(lambda: sa.delete_security_requirement_pack(packId=pack_id))

    req_a = ctx.unique_name("sim2real-behav-req-a-")
    req_b = ctx.unique_name("sim2real-behav-req-b-")

    first = sa.batch_create_security_requirements(
        packId=pack_id,
        securityRequirements=[
            {"name": req_a, "description": "desc-a", "domain": "encryption", "evaluation": "eval-a"}
        ],
    )
    assert first["errors"] == [], first

    second = sa.batch_create_security_requirements(
        packId=pack_id,
        securityRequirements=[
            {"name": req_a, "description": "desc-a-dup", "domain": "encryption", "evaluation": "eval-a"},
            {"name": req_b, "description": "desc-b", "domain": "logging", "evaluation": "eval-b"},
        ],
    )

    error_names = {e["securityRequirementName"]: e["code"] for e in second["errors"]}
    assert error_names.get(req_a) == "ConflictException", error_names
    assert error_names.get(req_b) == "NotProcessed", error_names
    # nothing was actually created by the partially-failed batch
    assert second["securityRequirements"] == [], second["securityRequirements"]

    # effect absent: still exactly one requirement named req_a, with its original
    # description, and req_b was never created (transactional rollback of the whole batch)
    listed = sa.list_security_requirements(packId=pack_id)["securityRequirementSummaries"]
    a_entries = [r for r in listed if r["name"] == req_a]
    assert len(a_entries) == 1, a_entries
    assert a_entries[0]["description"] == "desc-a", a_entries[0]
    listed_names = {r["name"] for r in listed}
    assert req_b not in listed_names, f"expected {req_b} never created by the partially-failed batch, got {listed_names}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

