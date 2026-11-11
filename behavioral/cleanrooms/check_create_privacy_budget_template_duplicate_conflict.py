"""create-privacy-budget-template-duplicate-conflict."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-privacy-budget-template-duplicate-conflict"
GROUP = "error-semantics"
SERVICES = ["cleanrooms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second DIFFERENTIAL_PRIVACY budget template in one membership fails with ConflictException, the
    exact message and reason ALREADY_EXISTS, leaving the original epsilon 10; once the original is deleted,
    the identical call succeeds and the new template is listed."""
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

    # Positive control: the first template of this budget type is created cleanly.
    template = cr.create_privacy_budget_template(
        membershipIdentifier=membership_id,
        autoRefresh="NONE",
        privacyBudgetType="DIFFERENTIAL_PRIVACY",
        parameters={"differentialPrivacy": {"epsilon": 10, "usersNoisePerQuery": 30}},
    )["privacyBudgetTemplate"]
    template_id = template["id"]
    live_template_ids = [template_id]
    ctx.on_cleanup(lambda: _delete_if_present(cr, membership_id, live_template_ids))

    # Break exactly one thing: a second template of the SAME budget type.
    error = _client_error(lambda: cr.create_privacy_budget_template(
        membershipIdentifier=membership_id,
        autoRefresh="NONE",
        privacyBudgetType="DIFFERENTIAL_PRIVACY",
        parameters={"differentialPrivacy": {"epsilon": 5, "usersNoisePerQuery": 50}},
    ))
    assert error.get("Error", {}).get("Code") == "ConflictException", (
        f'a second CreatePrivacyBudgetTemplate of the same budget type was rejected '
        f'with {error.get("Error", {}).get("Code")!r}, expected "ConflictException"'
    )
    assert error.get("Error", {}).get("Message") == (
        f"A Privacy Budget Template for Differential Privacy already exists in collaboration {collab_id}."
    ), error
    assert error.get("reason") == "ALREADY_EXISTS", (
        f'the ConflictException reason was {error.get("reason")!r} '
        f'(full error: {error!r}), expected "ALREADY_EXISTS"'
    )

    # Effect absent: the original template's parameters are untouched.
    still = cr.get_privacy_budget_template(
        membershipIdentifier=membership_id, privacyBudgetTemplateIdentifier=template_id
    )["privacyBudgetTemplate"]
    still_epsilon = still["parameters"]["differentialPrivacy"]["epsilon"]
    assert still_epsilon == 10, (
        f'the rejected duplicate create moved epsilon to {still_epsilon}, expected '
        f'it to remain 10'
    )

    # Restore: remove the conflicting template via an independent op, confirm it is
    # gone at an independent read, then the identical call that was refused above
    # must now succeed.
    cr.delete_privacy_budget_template(
        membershipIdentifier=membership_id, privacyBudgetTemplateIdentifier=template_id)
    live_template_ids.remove(template_id)

    gone = _client_error(lambda: cr.get_privacy_budget_template(
        membershipIdentifier=membership_id, privacyBudgetTemplateIdentifier=template_id))
    assert gone.get("Error", {}).get("Code") == "ResourceNotFoundException", (
        f'reading the deleted template returned {gone.get("Error", {}).get("Code")!r}, '
        f'expected "ResourceNotFoundException"'
    )
    assert gone.get("Error", {}).get("Message") == (
        f"No privacy budget template found with id {template_id} for membership {membership_id}."
    ), gone

    restored = cr.create_privacy_budget_template(
        membershipIdentifier=membership_id,
        autoRefresh="NONE",
        privacyBudgetType="DIFFERENTIAL_PRIVACY",
        parameters={"differentialPrivacy": {"epsilon": 5, "usersNoisePerQuery": 50}},
    )["privacyBudgetTemplate"]
    restored_id = restored["id"]
    live_template_ids.append(restored_id)

    restored_full = cr.get_privacy_budget_template(
        membershipIdentifier=membership_id, privacyBudgetTemplateIdentifier=restored_id
    )["privacyBudgetTemplate"]
    restored_epsilon = restored_full["parameters"]["differentialPrivacy"]["epsilon"]
    assert restored_epsilon == 5, (
        f'the template created once the conflict was cleared has epsilon '
        f'{restored_epsilon}, expected 5'
    )

    # Terminal read: independent of every mutating call above, at the destination.
    templates = cr.list_privacy_budget_templates(membershipIdentifier=membership_id)[
        "privacyBudgetTemplateSummaries"
    ]
    assert any(t["id"] == restored_id for t in templates), (
        f'the template created once the conflict was cleared, {restored_id!r}, does '
        f'not appear in ListPrivacyBudgetTemplates: {templates!r}'
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


def _client_error(fn):
    """Call fn(); return its full parsed error response (Code/Message under
    "Error", modeled fields like "reason" at the top level). An unexpected success
    raises, so a target that accepts input AWS refuses fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(
        f'real AWS rejects this call, but it SUCCEEDED and returned {result!r}')


def _delete_if_present(cr, membership_id, template_ids):
    for template_id in list(template_ids):
        try:
            cr.delete_privacy_budget_template(
                membershipIdentifier=membership_id,
                privacyBudgetTemplateIdentifier=template_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
