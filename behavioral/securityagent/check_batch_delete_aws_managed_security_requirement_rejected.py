"""batch-delete-aws-managed-security-requirement-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "batch-delete-aws-managed-security-requirement-rejected"
GROUP = "overly-permissive"
SERVICES = ["securityagent"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """BatchDeleteSecurityRequirements on an AWS-managed pack is refused at the call level with
    ValidationException and its exact message, and the requirement stays listed; deleting a
    customer-managed requirement still succeeds and a later read reports it ResourceNotFound."""
    sa = ctx.client("securityagent")

    managed_pack = None
    for pack in sa.list_security_requirement_packs()["securityRequirementPackSummaries"]:
        if pack["managementType"] == "AWS_MANAGED":
            managed_pack = pack
            break
    if managed_pack is None:
        raise AssertionError(
            "no AWS_MANAGED security requirement pack found in this account; cannot "
            "probe the protected-pack rejection without one. Would be closed by "
            "seeding the account/emulator with an AWS-managed pack."
        )

    reqs = sa.list_security_requirements(packId=managed_pack["packId"])["securityRequirementSummaries"]
    if not reqs:
        raise AssertionError(
            f"AWS_MANAGED pack {managed_pack['packId']} has no security requirements to "
            "probe the protected-pack rejection against."
        )
    protected_name = reqs[0]["name"]

    try:
        result = sa.batch_delete_security_requirements(
            packId=managed_pack["packId"], securityRequirementNames=[protected_name]
        )
    except ClientError as e:
        raised = e.response["Error"]["Code"]
        message = e.response["Error"].get("Message")
    else:
        raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")
    assert raised == "ValidationException", f"expected call-level ValidationException, got {raised!r}"
    expected = f"Only customer managed packs support deleting security requirements. Pack ID: {managed_pack['packId']}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: the AWS-managed requirement is still there
    still_there = sa.batch_get_security_requirements(
        packId=managed_pack["packId"], securityRequirementNames=[protected_name]
    )
    still_there_names = {r["name"] for r in still_there["securityRequirements"]}
    assert protected_name in still_there_names, (protected_name, still_there_names)

    # positive control: deleting a customer-managed requirement in an owned pack works
    own_pack_id = sa.create_security_requirement_pack(name=ctx.unique_name("sim2real-behav-pack-"))["packId"]
    ctx.on_cleanup(lambda: sa.delete_security_requirement_pack(packId=own_pack_id))
    own_req = ctx.unique_name("sim2real-behav-req-")
    sa.batch_create_security_requirements(
        packId=own_pack_id,
        securityRequirements=[{"name": own_req, "description": "d", "domain": "iam", "evaluation": "e"}],
    )
    own_delete = sa.batch_delete_security_requirements(packId=own_pack_id, securityRequirementNames=[own_req])
    assert own_delete["deletedSecurityRequirementNames"] == [own_req], own_delete
    assert own_delete["errors"] == [], own_delete

    # independent read at the destination: the customer-managed requirement is actually
    # gone, not merely reported as deleted by the delete call's own response
    after_delete = sa.batch_get_security_requirements(packId=own_pack_id, securityRequirementNames=[own_req])
    assert after_delete["securityRequirements"] == []
    gone_codes = {e["securityRequirementName"]: e["code"] for e in after_delete["errors"]}
    assert gone_codes.get(own_req) == "ResourceNotFound", gone_codes


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

