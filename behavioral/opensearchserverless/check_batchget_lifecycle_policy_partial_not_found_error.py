"""batchget-lifecycle-policy-partial-not-found-error."""
from __future__ import annotations

import json
import re
from typing import Any, Callable


from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "batchget-lifecycle-policy-partial-not-found-error"
GROUP = "error-semantics"
SERVICES = ["opensearchserverless"]

_FAKE_POLICY_NAME = "zzz-nonexistent-policy"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchGetLifecyclePolicy with a mix of a real identifier and an unknown one returns the
    real policy in lifecyclePolicyDetails and a per-identifier NOT_FOUND entry in
    lifecyclePolicyErrorDetails -- never a whole-request failure."""
    aoss = ctx.client("opensearchserverless")
    name = _short_name(ctx, "sim2real-bglcpol")

    policy = json.dumps(
        {"Rules": [{"ResourceType": "index", "Resource": [f"index/{name}*/*"], "MinIndexRetention": "24h"}]}
    )
    created = aoss.create_lifecycle_policy(type="retention", name=name, policy=policy)[
        "lifecyclePolicyDetail"
    ]
    assert created["name"] == name, f"expected created policy name {name!r}, got {created['name']!r}"

    def _cleanup() -> None:
        try:
            aoss.delete_lifecycle_policy(type="retention", name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    resp = aoss.batch_get_lifecycle_policy(
        identifiers=[
            {"type": "retention", "name": name},
            {"type": "retention", "name": _FAKE_POLICY_NAME},
        ]
    )
    details = resp.get("lifecyclePolicyDetails", [])
    errors = resp.get("lifecyclePolicyErrorDetails", [])

    assert len(details) == 1, f"expected exactly one successful item, got {details}"
    assert details[0]["name"] == name, f"expected successful item named {name!r}, got {details[0]['name']!r}"

    assert len(errors) == 1, f"expected exactly one per-item error, got {errors}"
    assert errors[0]["name"] == _FAKE_POLICY_NAME, (
        f"expected the per-item error to name {_FAKE_POLICY_NAME!r}, got {errors[0]['name']!r}"
    )
    assert errors[0]["errorCode"] == "NOT_FOUND", (
        f"expected errorCode 'NOT_FOUND' for the never-created identifier, got {errors[0]['errorCode']!r}"
    )
    expected_item_message = "The specified Lifecycle Policy is not found."
    assert errors[0]["errorMessage"] == expected_item_message, (
        f"expected errorMessage {expected_item_message!r}, got {errors[0]!r}"
    )

    # Gone means unusable, not just unreadable. Delete the real policy explicitly (rather
    # than relying only on ctx.on_cleanup) and prove it now takes the same NOT_FOUND path as the
    # never-existed identifier, and that a mutation against it is also rejected.
    aoss.delete_lifecycle_policy(type="retention", name=name)

    resp2 = aoss.batch_get_lifecycle_policy(
        identifiers=[
            {"type": "retention", "name": name},
            {"type": "retention", "name": _FAKE_POLICY_NAME},
        ]
    )
    assert not resp2.get("lifecyclePolicyDetails"), (
        f"deleted policy still returned a detail: {resp2.get('lifecyclePolicyDetails')!r}"
    )
    errors2 = resp2.get("lifecyclePolicyErrorDetails", [])
    assert len(errors2) == 2, (
        f"expected NOT_FOUND for both the deleted and never-created names, got {errors2}"
    )
    assert {e["name"] for e in errors2} == {name, _FAKE_POLICY_NAME}, (
        f"expected NOT_FOUND entries for {name!r} and {_FAKE_POLICY_NAME!r}, got {errors2!r}"
    )
    assert all(e["errorCode"] == "NOT_FOUND" for e in errors2), (
        f"expected errorCode 'NOT_FOUND' for both entries, got {errors2!r}"
    )
    by_name = {e["name"]: e["errorMessage"] for e in errors2}
    expected_by_name = {name: "The specified Lifecycle Policy is not found.", _FAKE_POLICY_NAME: "The specified Lifecycle Policy is not found."}
    assert by_name == expected_by_name, f"expected errorMessages {expected_by_name!r}, got {by_name!r}"

    code, message = _error(
        lambda: aoss.update_lifecycle_policy(
            type="retention",
            name=name,
            policyVersion=created["policyVersion"],
            policy=policy,
        )
    )
    assert code == "ResourceNotFoundException", (
        f"update_lifecycle_policy on the deleted policy returned {code!r}, expected "
        f"'ResourceNotFoundException'"
    )
    expected_message = f"Policy with name {name} and type retention is not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
