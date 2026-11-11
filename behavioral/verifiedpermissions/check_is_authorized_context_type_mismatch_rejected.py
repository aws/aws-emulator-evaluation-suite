"""is-authorized-context-type-mismatch-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "is-authorized-context-type-mismatch-rejected"
GROUP = "overly-permissive"
SERVICES = ["verifiedpermissions"]


@tags("axis:happy-path", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """With a schema-declared Long context attribute, a `>` condition on a mistyped value yields DENY with
    an evaluation error and no determining policies, while a Long value yields ALLOW with no errors,
    determined by that policy."""
    client = ctx.client("verifiedpermissions")
    store_id = _create_policy_store(ctx, client)
    schema = {
        "PhotoApp": {
            "entityTypes": {"User": {}, "Photo": {}},
            "actions": {
                "viewPhoto": {
                    "appliesTo": {
                        "principalTypes": ["User"],
                        "resourceTypes": ["Photo"],
                        "context": {
                            "type": "Record",
                            "attributes": {"count": {"type": "Long", "required": True}},
                        },
                    }
                }
            },
        }
    }
    client.put_schema(policyStoreId=store_id, definition={"cedarJson": json.dumps(schema)})

    statement = (
        'permit(principal == PhotoApp::User::"alice", action == PhotoApp::Action::"viewPhoto", '
        'resource == PhotoApp::Photo::"vacation.jpg") when { context.count > 0 };'
    )
    policy_id = client.create_policy(
        policyStoreId=store_id, definition={"static": {"statement": statement}}
    )["policyId"]
    ctx.on_cleanup(lambda: client.delete_policy(policyStoreId=store_id, policyId=policy_id))

    base_kwargs = dict(
        policyStoreId=store_id,
        principal={"entityType": "PhotoApp::User", "entityId": "alice"},
        action={"actionType": "PhotoApp::Action", "actionId": "viewPhoto"},
        resource={"entityType": "PhotoApp::Photo", "entityId": "vacation.jpg"},
    )

    resp_mismatch = _retry_until_ready(
        lambda: client.is_authorized(
            context={"contextMap": {"count": {"boolean": True}}}, **base_kwargs
        )
    )
    assert resp_mismatch["decision"] == "DENY", (
        f"expected DENY on context type mismatch, got {resp_mismatch['decision']}"
    )
    assert resp_mismatch["errors"], "expected a type-mismatch evaluation error, got none"
    assert resp_mismatch["determiningPolicies"] == [], (
        "a policy whose `when` clause errors on evaluation must not determine the "
        f"decision, got {resp_mismatch['determiningPolicies']}"
    )

    # positive control: a context value of the schema-declared type is accepted.
    resp = _retry_until_ready(
        lambda: client.is_authorized(
            context={"contextMap": {"count": {"long": 5}}}, **base_kwargs
        )
    )
    assert resp["decision"] == "ALLOW", f"expected ALLOW for a well-typed context, got {resp['decision']}"
    assert resp["errors"] == [], f"expected no evaluation errors, got {resp['errors']}"
    assert resp["determiningPolicies"] == [{"policyId": policy_id}], (
        f"expected the permit policy to determine the ALLOW, got {resp['determiningPolicies']}"
    )


def _create_policy_store(ctx, client, mode: str = "OFF") -> str:
    store_id = client.create_policy_store(
        validationSettings={"mode": mode}, tags={"sim2real": "true"}
    )["policyStoreId"]
    ctx.on_cleanup(lambda: client.delete_policy_store(policyStoreId=store_id))
    return store_id


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    return None


def _retry_until_ready(fn, timeout: float = 30.0, interval: float = 1.5):
    """Newly created policy stores/schemas can lag briefly before the
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


def _error_code_retry(fn, timeout: float = 30.0, interval: float = 1.5):
    """Like _error_code, but treats a transient ResourceNotFoundException
    (store just created, data plane hasn't caught up yet) as "not ready" and
    retries instead of treating it as the terminal outcome."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.time() + timeout
    while True:
        try:
            fn()
            return None
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException" and time.time() < deadline:
                time.sleep(interval)
                continue
            return code


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

