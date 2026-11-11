"""batch-delete-security-requirements-partial-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-delete-security-requirements-partial-not-found"
GROUP = "error-semantics"
SERVICES = ["securityagent"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """BatchDeleteSecurityRequirements mixing a real name with a bogus one deletes nothing: the bogus
    name reports ResourceNotFound, the real one NotProcessed and stays listed; deleted on its own, the
    real requirement is removed."""
    sa = ctx.client("securityagent")
    pack_id = sa.create_security_requirement_pack(
        name=ctx.unique_name("sim2real-behav-pack-"), tags={"sim2real": "behavioral"}
    )["packId"]
    ctx.on_cleanup(lambda: sa.delete_security_requirement_pack(packId=pack_id))

    req_c = ctx.unique_name("sim2real-behav-req-c-")
    bogus_name = ctx.unique_name("sim2real-behav-req-bogus-")

    sa.batch_create_security_requirements(
        packId=pack_id,
        securityRequirements=[
            {"name": req_c, "description": "desc-c", "domain": "iam", "evaluation": "eval-c"}
        ],
    )

    result = sa.batch_delete_security_requirements(
        packId=pack_id, securityRequirementNames=[req_c, bogus_name]
    )
    assert result["deletedSecurityRequirementNames"] == [], result
    error_names = {e["securityRequirementName"]: e["code"] for e in result["errors"]}
    assert error_names.get(bogus_name) == "ResourceNotFound", error_names
    assert error_names.get(req_c) == "NotProcessed", error_names

    # effect absent: req_c was NOT deleted — the whole batch rolled back together
    listed = sa.list_security_requirements(packId=pack_id)["securityRequirementSummaries"]
    names = {r["name"] for r in listed}
    assert req_c in names, f"expected {req_c} untouched by the partially-failed batch, got {names}"

    # positive control: deleting req_c on its own (no bogus co-passenger) does work
    solo = sa.batch_delete_security_requirements(packId=pack_id, securityRequirementNames=[req_c])
    assert solo["deletedSecurityRequirementNames"] == [req_c], solo
    assert solo["errors"] == [], solo

    # independent terminal read: the solo delete actually took effect at the destination
    remaining = {
        r["name"] for r in sa.list_security_requirements(packId=pack_id)["securityRequirementSummaries"]
    }
    assert req_c not in remaining, f"expected {req_c} gone after solo delete, still listed: {remaining}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

