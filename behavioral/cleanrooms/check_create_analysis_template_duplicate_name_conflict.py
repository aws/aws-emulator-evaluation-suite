"""create-analysis-template-duplicate-name-conflict."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-analysis-template-duplicate-name-conflict"
GROUP = "error-semantics"
SERVICES = ["cleanrooms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating a second analysis template with the same name in the same
    membership is rejected with ConflictException, and only the original template
    exists afterward."""
    cr = ctx.client("cleanrooms")

    collab_id = cr.create_collaboration(
        name=ctx.unique_name("sim2real-cr-collab-"),
        description="behavioral fidelity check",
        members=[],
        creatorMemberAbilities=["CAN_QUERY", "CAN_RECEIVE_RESULTS"],
        creatorDisplayName="creator",
        queryLogStatus="DISABLED",
    )["collaboration"]["id"]
    membership_ids = []
    ctx.on_cleanup(lambda: _delete_collaboration_then_memberships(cr, collab_id, membership_ids))

    membership_id = cr.create_membership(
        collaborationIdentifier=collab_id, queryLogStatus="DISABLED"
    )["membership"]["id"]
    membership_ids.append(membership_id)

    name = ctx.unique_name("sim2real_cr_tpl_").replace("-", "_")
    template = cr.create_analysis_template(
        membershipIdentifier=membership_id,
        name=name,
        format="SQL",
        source={"text": "SELECT 1 AS one"},
    )["analysisTemplate"]
    template_id = template["id"]
    ctx.on_cleanup(lambda: cr.delete_analysis_template(
        membershipIdentifier=membership_id, analysisTemplateIdentifier=template_id))

    code, message = _error_code(lambda: cr.create_analysis_template(
        membershipIdentifier=membership_id,
        name=name,
        format="SQL",
        source={"text": "SELECT 2 AS two"},
    ))
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    # The message opens with a server-chosen id, so its stable prefix and membership suffix are asserted.
    assert message.startswith("The ") and message.endswith(
        f": with membership id: {membership_id} already exists."
    ), f"expected the duplicate-template conflict naming membership {membership_id}, got {message!r}"

    templates = cr.list_analysis_templates(membershipIdentifier=membership_id)["analysisTemplateSummaries"]
    matching = [t for t in templates if t["name"] == name]
    assert len(matching) == 1, f"expected exactly one template named {name!r}, got {matching!r}"
    assert matching[0]["id"] == template_id, f"expected {template_id}, got {matching[0]['id']}"

    # Positive control: a template with a different name still succeeds, and
    # the terminal read confirms both templates independently at the destination.
    other_name = ctx.unique_name("sim2real_cr_tpl2_").replace("-", "_")
    other_id = cr.create_analysis_template(
        membershipIdentifier=membership_id,
        name=other_name,
        format="SQL",
        source={"text": "SELECT 3 AS three"},
    )["analysisTemplate"]["id"]
    ctx.on_cleanup(lambda: cr.delete_analysis_template(
        membershipIdentifier=membership_id, analysisTemplateIdentifier=other_id))

    templates_after = cr.list_analysis_templates(membershipIdentifier=membership_id)["analysisTemplateSummaries"]
    names_after = {t["name"]: t["id"] for t in templates_after}
    assert names_after.get(other_name) == other_id, (
        f"expected {other_name!r} -> {other_id} in {names_after!r}"
    )
    assert names_after.get(name) == template_id, (
        f"expected original {name!r} -> {template_id} still present in {names_after!r}"
    )


def _delete_collaboration_then_memberships(cr, collab_id, membership_ids):
    """The creator's ACTIVE membership cannot be deleted, so the collaboration goes first and
    each membership is deleted once it reads COLLABORATION_DELETED."""
    cr.delete_collaboration(collaborationIdentifier=collab_id)
    for membership_id in membership_ids:
        deadline = time.monotonic() + 60
        status = None
        while time.monotonic() < deadline:
            status = cr.get_membership(membershipIdentifier=membership_id)["membership"]["status"]
            if status == "COLLABORATION_DELETED":
                break
            time.sleep(2)
        else:
            raise AssertionError(f"membership {membership_id} never reached COLLABORATION_DELETED: {status}")
        cr.delete_membership(membershipIdentifier=membership_id)


def _error_code(fn):
    """Call fn(); return its error code and message. An unexpected success raises, so a
    target that accepts a duplicate name AWS rejects fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected rejection but call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
