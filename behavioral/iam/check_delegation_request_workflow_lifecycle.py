"""delegation-request-workflow-lifecycle."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delegation-request-workflow-lifecycle"
GROUP = 'delegation_requests'
SERVICES = ['iam']


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Delegation-request ops reject an out-of-range SessionDuration (ValidationError) and a
    never-created request id (NoSuchEntity); AcquireRole on an unknown template is NoSuchEntity.
    """
    iam = ctx.client("iam")
    workflow_id = ctx.unique_name("sim2real-behav-wf-")
    fake_notification_arn = f"arn:aws:sns:{ctx.region}:111122223333:sim2real-behav-topic"

    # (1) SessionDuration above 43200 reaches IAM's server-side check: botocore validates only
    # the modeled minimum client-side. CreateDelegationRequest otherwise needs partner onboarding.
    code_create, message_create = _error(
        lambda: iam.create_delegation_request(
            Description="sim2real-behav delegation probe",
            NotificationChannel=fake_notification_arn,
            Permissions={
                "PolicyTemplateArn": "arn:aws:iam:::delegation-template/partner_delegation_template"
            },
            RequestorWorkflowId=workflow_id,
            SessionDuration=999999,
        )
    )
    assert code_create == "ValidationError", (
        f"expected ValidationError for out-of-range SessionDuration, got {code_create}"
    )
    expected_create = (
        "1 validation error detected: Value at 'sessionDuration' failed to satisfy constraint: "
        "Member must have value less than or equal to 43200"
    )
    assert message_create == expected_create, (
        f"expected message {expected_create!r}, got {message_create!r}"
    )

    # (2) A syntactically-valid but never-created DelegationRequestId drives NoSuchEntity across
    # every request-scoped op.
    fake_id = f"sim2real-behav-{uuid.uuid4().hex}"
    # Get and Accept spell the entity "DelegationRequest"; the other request-scoped ops spell it
    # "Delegation request".
    expected_compact = f"DelegationRequest not found: {fake_id}"
    expected_spaced = f"Delegation request not found: {fake_id}"

    code_get, message_get = _error(lambda: iam.get_delegation_request(DelegationRequestId=fake_id))
    assert code_get == "NoSuchEntity", f"expected NoSuchEntity for GetDelegationRequest, got {code_get}"
    assert message_get == expected_compact, f"expected message {expected_compact!r}, got {message_get!r}"

    resp_list = iam.list_delegation_requests()
    assert "DelegationRequests" in resp_list, "ListDelegationRequests must return a DelegationRequests list"

    code_update, message_update = _error(
        lambda: iam.update_delegation_request(DelegationRequestId=fake_id, Notes="sim2real-behav")
    )
    assert code_update == "NoSuchEntity", (
        f"expected NoSuchEntity for UpdateDelegationRequest, got {code_update}"
    )
    assert message_update == expected_spaced, f"expected message {expected_spaced!r}, got {message_update!r}"

    code_accept, message_accept = _error(
        lambda: iam.accept_delegation_request(DelegationRequestId=fake_id)
    )
    assert code_accept == "NoSuchEntity", (
        f"expected NoSuchEntity for AcceptDelegationRequest, got {code_accept}"
    )
    assert message_accept == expected_compact, f"expected message {expected_compact!r}, got {message_accept!r}"

    code_reject, message_reject = _error(
        lambda: iam.reject_delegation_request(DelegationRequestId=fake_id)
    )
    assert code_reject == "NoSuchEntity", (
        f"expected NoSuchEntity for RejectDelegationRequest, got {code_reject}"
    )
    assert message_reject == expected_spaced, f"expected message {expected_spaced!r}, got {message_reject!r}"

    code_assoc, message_assoc = _error(
        lambda: iam.associate_delegation_request(DelegationRequestId=fake_id)
    )
    assert code_assoc == "NoSuchEntity", (
        f"expected NoSuchEntity for AssociateDelegationRequest, got {code_assoc}"
    )
    assert message_assoc == expected_spaced, f"expected message {expected_spaced!r}, got {message_assoc!r}"

    code_send, message_send = _error(
        lambda: iam.send_delegation_token(DelegationRequestId=fake_id)
    )
    assert code_send == "NoSuchEntity", (
        f"expected NoSuchEntity for SendDelegationToken, got {code_send}"
    )
    assert message_send == expected_spaced, f"expected message {expected_spaced!r}, got {message_send!r}"

    # None of the rejected mutation attempts above may have fabricated a request under
    # fake_id: an independent read must still see it as unresolvable.
    code_get_after, message_get_after = _error(lambda: iam.get_delegation_request(DelegationRequestId=fake_id))
    assert code_get_after == "NoSuchEntity", (
        f"expected {fake_id} to remain unresolvable via GetDelegationRequest after every "
        f"rejected mutation attempt on it, got {code_get_after}"
    )
    assert message_get_after == expected_compact, f"expected message {expected_compact!r}, got {message_get_after!r}"

    # (3) AcquireRole: a made-up (non-existent) role-template ARN must be rejected with the
    # specific NoSuchEntity code, and no role is fabricated from the template's basename.
    bogus_role_name = "sim2real-behav-nonexistent"
    code_acquire, message_acquire = _error(
        lambda: iam.acquire_role(
            TemplateArn=f"arn:aws:iam::aws:role-template/{bogus_role_name}:1"
        )
    )
    assert code_acquire == "NoSuchEntity", (
        f"expected NoSuchEntity for a bogus role template ARN, got {code_acquire}"
    )
    expected_acquire = f"Role template not found: arn:aws:iam::aws:role-template/{bogus_role_name}:1"
    assert message_acquire == expected_acquire, (
        f"expected message {expected_acquire!r}, got {message_acquire!r}"
    )
    code_role_after, message_role_after = _error(lambda: iam.get_role(RoleName=bogus_role_name))
    assert code_role_after == "NoSuchEntity", (
        f"no role should have been created from a rejected AcquireRole template acquisition, "
        f"got {code_role_after}"
    )
    expected_role_after = f"The role with name {bogus_role_name} cannot be found."
    assert message_role_after == expected_role_after, (
        f"expected message {expected_role_after!r}, got {message_role_after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
