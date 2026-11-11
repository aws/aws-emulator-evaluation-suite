"""is-authorized-entity-hierarchy-grants-via-group."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "is-authorized-entity-hierarchy-grants-via-group"
GROUP = "data-plane"
SERVICES = ["verifiedpermissions"]


@tags("axis:happy-path", "cap:c7", "plane:control")
def run(ctx) -> None:
    """A policy that grants access to a UserGroup applies transitively to a
    principal that is a member of that group, when the group membership is
    supplied via the entities parameter (Cedar entity-hierarchy resolution)."""
    client = ctx.client("verifiedpermissions")
    store_id = _create_policy_store(ctx, client)
    statement = (
        'permit(principal in UserGroup::"admins", action == Action::"viewPhoto", '
        'resource == Photo::"vacation.jpg");'
    )
    policy_id = client.create_policy(
        policyStoreId=store_id, definition={"static": {"statement": statement}}
    )["policyId"]
    ctx.on_cleanup(lambda: client.delete_policy(policyStoreId=store_id, policyId=policy_id))

    entities = {
        "entityList": [
            {
                "identifier": {"entityType": "User", "entityId": "alice"},
                "parents": [{"entityType": "UserGroup", "entityId": "admins"}],
            },
            {"identifier": {"entityType": "UserGroup", "entityId": "admins"}},
        ]
    }

    def call_alice(entity_list):
        return client.is_authorized(
            policyStoreId=store_id,
            principal={"entityType": "User", "entityId": "alice"},
            action={"actionType": "Action", "actionId": "viewPhoto"},
            resource={"entityType": "Photo", "entityId": "vacation.jpg"},
            entities={"entityList": entity_list},
        )

    allowed = _retry_until_ready(lambda: call_alice(entities["entityList"]))
    assert allowed["decision"] == "ALLOW", f"expected ALLOW for group member, got {allowed}"
    assert allowed["determiningPolicies"] == [{"policyId": policy_id}], (
        f"expected the permit policy {policy_id} to determine the decision, got {allowed['determiningPolicies']}"
    )

    # Same principal, same action/resource, but the entity hierarchy no longer
    # declares alice as a member of the group (her `parents` link is dropped,
    # even though a UserGroup::"admins" entity still exists in the entityList).
    # This isolates the hierarchy resolution itself: a target that grants
    # access merely because a matching UserGroup entity is *present* somewhere
    # in entities -- rather than because the principal is actually linked to it
    # via `parents` -- would wrongly ALLOW here.
    unlinked = call_alice(
        [
            {"identifier": {"entityType": "User", "entityId": "alice"}},
            {"identifier": {"entityType": "UserGroup", "entityId": "admins"}},
        ]
    )
    assert unlinked["decision"] == "DENY", (
        f"alice with no parents link to UserGroup::admins must be denied, got {unlinked}"
    )
    assert unlinked["determiningPolicies"] == [], (
        f"a DENY must cite no determining permit policy, got {unlinked['determiningPolicies']}"
    )

    # A principal that is NOT a member of the group is not granted access.
    denied = client.is_authorized(
        policyStoreId=store_id,
        principal={"entityType": "User", "entityId": "bob"},
        action={"actionType": "Action", "actionId": "viewPhoto"},
        resource={"entityType": "Photo", "entityId": "vacation.jpg"},
        entities={"entityList": [{"identifier": {"entityType": "User", "entityId": "bob"}}]},
    )
    assert denied["decision"] == "DENY", f"expected DENY for a non-member principal, got {denied}"
    assert denied["determiningPolicies"] == [], (
        f"a DENY must cite no determining permit policy, got {denied['determiningPolicies']}"
    )


def _create_policy_store(ctx, client, mode: str = "OFF") -> str:
    store_id = client.create_policy_store(
        validationSettings={"mode": mode},
        tags={"simparity-check": CHECK},
    )["policyStoreId"]
    ctx.on_cleanup(lambda: client.delete_policy_store(policyStoreId=store_id))
    return store_id


def _retry_until_ready(fn, timeout: float = 30.0, interval: float = 1.5):
    """Newly created policy stores/policies can lag briefly before the
    authorization data plane sees them; retry on ResourceNotFoundException
    up to timeout seconds before giving up."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.time() + timeout
    last_exc = None
    while time.time() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            last_exc = exc
            time.sleep(interval)
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
