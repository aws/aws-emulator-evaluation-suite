"""batch-create-security-requirements-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-create-security-requirements-round-trip"
GROUP = "data-plane"
SERVICES = ["securityagent"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchCreateSecurityRequirements persists all entries: they show up via
    ListSecurityRequirements and BatchGetSecurityRequirements with matching fields."""
    sa = ctx.client("securityagent")
    pack_id = sa.create_security_requirement_pack(name=ctx.unique_name("sim2real-behav-pack-"))["packId"]
    ctx.on_cleanup(lambda: sa.delete_security_requirement_pack(packId=pack_id))

    req_a = ctx.unique_name("sim2real-behav-req-a-")
    req_b = ctx.unique_name("sim2real-behav-req-b-")
    entries = [
        {"name": req_a, "description": "desc-a", "domain": "encryption", "evaluation": "eval-a"},
        {"name": req_b, "description": "desc-b", "domain": "logging", "evaluation": "eval-b"},
    ]

    def _delete_reqs():
        sa.batch_delete_security_requirements(packId=pack_id, securityRequirementNames=[req_a, req_b])

    ctx.on_cleanup(_delete_reqs)

    result = sa.batch_create_security_requirements(packId=pack_id, securityRequirements=entries)
    assert result["errors"] == [], f"expected no batch-create errors, got {result['errors']}"
    created_names = {r["name"] for r in result["securityRequirements"]}
    assert created_names == {req_a, req_b}, f"expected {{{req_a!r}, {req_b!r}}}, got {created_names}"

    listed = sa.list_security_requirements(packId=pack_id)["securityRequirementSummaries"]
    listed_names = {r["name"] for r in listed}
    assert {req_a, req_b}.issubset(listed_names), (
        f"expected {req_a!r} and {req_b!r} in list, got {listed_names}"
    )

    got = sa.batch_get_security_requirements(packId=pack_id, securityRequirementNames=[req_a, req_b])
    assert got["errors"] == [], f"expected no batch-get errors, got {got['errors']}"
    by_name = {r["name"]: r for r in got["securityRequirements"]}
    assert by_name[req_a]["description"] == "desc-a", by_name[req_a]
    assert by_name[req_a]["domain"] == "encryption", by_name[req_a]
    assert by_name[req_a]["evaluation"] == "eval-a", by_name[req_a]
    assert by_name[req_b]["description"] == "desc-b", by_name[req_b]
    assert by_name[req_b]["domain"] == "logging", by_name[req_b]
    assert by_name[req_b]["evaluation"] == "eval-b", by_name[req_b]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
