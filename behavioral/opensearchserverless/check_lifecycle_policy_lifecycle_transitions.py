"""lifecycle-policy-lifecycle-transitions."""
from __future__ import annotations

import json
import re
from typing import Any, Callable


from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lifecycle-policy-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["opensearchserverless"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """LifecyclePolicy created, batch-fetched, updated, then deleted -- after which it is both
    absent from a read and unusable as a mutation target, and the freed name is reusable."""
    aoss = ctx.client("opensearchserverless")
    name = _short_name(ctx, "sim2real-lcpol")
    ident = {"type": "retention", "name": name}

    policy_v1 = json.dumps(
        {
            "Rules": [
                {
                    "ResourceType": "index",
                    "Resource": [f"index/{name}*/*"],
                    "MinIndexRetention": "24h",
                }
            ]
        }
    )

    created = aoss.create_lifecycle_policy(
        type="retention",
        name=name,
        description="sim2real behavioral retention policy",
        policy=policy_v1,
    )["lifecyclePolicyDetail"]
    version1 = created["policyVersion"]
    assert created["type"] == "retention", f"expected type 'retention', got {created['type']!r}"
    assert _norm(created["policy"]) == _norm(policy_v1), (
        f"created policy body {created['policy']!r} does not round-trip {policy_v1!r}"
    )

    def _cleanup() -> None:
        try:
            aoss.delete_lifecycle_policy(type="retention", name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    got = aoss.batch_get_lifecycle_policy(identifiers=[ident])
    assert len(got["lifecyclePolicyDetails"]) == 1, (
        f"expected exactly one lifecycle policy detail, got {got['lifecyclePolicyDetails']!r}"
    )
    assert got["lifecyclePolicyDetails"][0]["policyVersion"] == version1, (
        f"batch_get policyVersion {got['lifecyclePolicyDetails'][0]['policyVersion']!r} != "
        f"create's {version1!r}"
    )
    assert not got.get("lifecyclePolicyErrorDetails"), (
        f"a fresh, existing policy reported per-item errors: {got.get('lifecyclePolicyErrorDetails')!r}"
    )

    policy_v2 = json.dumps(
        {
            "Rules": [
                {
                    "ResourceType": "index",
                    "Resource": [f"index/{name}*/*"],
                    "MinIndexRetention": "48h",
                }
            ]
        }
    )
    updated = aoss.update_lifecycle_policy(
        type="retention", name=name, policyVersion=version1, policy=policy_v2
    )["lifecyclePolicyDetail"]
    assert updated["policyVersion"] != version1, (
        f"policyVersion did not change after a successful update; still {version1!r}"
    )
    assert _norm(updated["policy"]) == _norm(policy_v2), (
        f"updated policy body {updated['policy']!r} does not round-trip {policy_v2!r}"
    )

    got2 = aoss.batch_get_lifecycle_policy(identifiers=[ident])
    assert _norm(got2["lifecyclePolicyDetails"][0]["policy"]) == _norm(policy_v2), (
        f"independent read after update saw {got2['lifecyclePolicyDetails'][0]['policy']!r}, "
        f"expected the v2 body {policy_v2!r}"
    )

    aoss.delete_lifecycle_policy(type="retention", name=name)

    got3 = aoss.batch_get_lifecycle_policy(identifiers=[ident])
    assert not got3["lifecyclePolicyDetails"], (
        f"deleted policy still returned a detail: {got3['lifecyclePolicyDetails']!r}"
    )
    assert got3["lifecyclePolicyErrorDetails"][0]["errorCode"] == "NOT_FOUND", (
        f"expected errorCode 'NOT_FOUND' for the deleted policy, got "
        f"{got3['lifecyclePolicyErrorDetails'][0]['errorCode']!r}"
    )
    assert got3["lifecyclePolicyErrorDetails"][0]["name"] == name, (
        f"NOT_FOUND error named {got3['lifecyclePolicyErrorDetails'][0]['name']!r}, expected {name!r}"
    )
    expected_item_message = "The specified Lifecycle Policy is not found."
    assert got3["lifecyclePolicyErrorDetails"][0]["errorMessage"] == expected_item_message, (
        f"expected errorMessage {expected_item_message!r}, got {got3['lifecyclePolicyErrorDetails'][0]!r}"
    )

    # Gone means unusable, not just unreadable -- a mutation on the dead identifier fails too.
    code, message = _error(
        lambda: aoss.update_lifecycle_policy(
            type="retention",
            name=name,
            policyVersion=updated["policyVersion"],
            policy=policy_v2,
        )
    )
    assert code == "ResourceNotFoundException", (
        f"update_lifecycle_policy on a deleted policy returned {code!r}, expected "
        f"'ResourceNotFoundException'"
    )
    expected_message = f"Policy with name {name} and type retention is not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # And the freed name is reusable: a fresh create-under-the-same-name succeeds cleanly.
    recreated = aoss.create_lifecycle_policy(
        type="retention", name=name, policy=policy_v1
    )["lifecyclePolicyDetail"]
    assert recreated["name"] == name, (
        f"recreating under the freed name {name!r} returned name {recreated['name']!r}"
    )
    assert recreated["policyVersion"] != updated["policyVersion"], (
        f"the recreated policy kept the old, deleted version {updated['policyVersion']!r}"
    )


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """(code, message) of the error ``fn`` raises. An unexpected success raises AssertionError, so a
    target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except Exception as exc:
        response = getattr(exc, "response", None)
        if response is None:
            raise
        return response["Error"]["Code"], response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _short_name(ctx: Any, prefix: str) -> str:
    raw = ctx.unique_name(prefix + "-").lower()
    raw = re.sub(r"[^a-z0-9-]", "", raw)
    if not raw or not raw[0].isalpha():
        raw = "a" + raw
    raw = raw[:32].rstrip("-")
    while len(raw) < 3:
        raw += "0"
    return raw


def _norm(v: Any) -> Any:
    """The policy field round-trips as a parsed object on read, a JSON string on write."""
    return json.loads(v) if isinstance(v, str) else v


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
