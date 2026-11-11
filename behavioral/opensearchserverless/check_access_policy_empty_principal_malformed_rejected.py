"""access-policy-empty-principal-malformed-rejected."""
from __future__ import annotations

import json
import re
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "access-policy-empty-principal-malformed-rejected"
GROUP = "error-semantics"
SERVICES = ["opensearchserverless"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAccessPolicy with an empty Principal list in its only statement is rejected with
    ValidationException rather than accepted as a no-op policy, while an otherwise-identical
    policy with a real principal creates successfully (positive control)."""
    aoss = ctx.client("opensearchserverless")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    empty_name = _short_name(ctx, "sim2real-emptyprin")
    valid_name = _short_name(ctx, "sim2real-validprin")

    empty_principal_policy = json.dumps(
        [
            {
                "Rules": [
                    {
                        "ResourceType": "index",
                        "Resource": [f"index/{empty_name}*/*"],
                        "Permission": ["aoss:ReadDocument"],
                    }
                ],
                "Principal": [],
            }
        ]
    )

    # negative: an empty Principal list is rejected
    code, message = _error(
        lambda: aoss.create_access_policy(type="data", name=empty_name, policy=empty_principal_policy)
    )
    assert code == "ValidationException", f"expected ValidationException for empty Principal, got {code!r}"
    expected_message = "Policy json is invalid, error: [$[0].Principal: there must be a minimum of 1 items in the array]"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: no access policy was created under that name
    not_found_code, not_found_message = _error(lambda: aoss.get_access_policy(type="data", name=empty_name))
    assert not_found_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for {empty_name!r}, got {not_found_code!r}"
    )
    expected_not_found = f"Policy with name {empty_name} and type data is not found"
    assert not_found_message == expected_not_found, (
        f"expected message {expected_not_found!r}, got {not_found_message!r}"
    )

    # positive control: the same statement shape with a real principal creates successfully
    principal = f"arn:aws:iam::{account_id}:role/{valid_name}-role"
    valid_policy = json.dumps(
        [
            {
                "Rules": [
                    {
                        "ResourceType": "index",
                        "Resource": [f"index/{valid_name}*/*"],
                        "Permission": ["aoss:ReadDocument"],
                    }
                ],
                "Principal": [principal],
            }
        ]
    )
    created = aoss.create_access_policy(type="data", name=valid_name, policy=valid_policy)[
        "accessPolicyDetail"
    ]
    assert created["name"] == valid_name, f"expected accessPolicyDetail.name={valid_name!r}, got {created!r}"

    def _cleanup() -> None:
        try:
            aoss.delete_access_policy(type="data", name=valid_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    # terminal read: independent of the mutating CreateAccessPolicy call, proving the
    # accepted policy is actually persisted and retrievable, not just echoed back
    got = aoss.get_access_policy(type="data", name=valid_name)["accessPolicyDetail"]
    assert got["policyVersion"] == created["policyVersion"], (
        f"expected GetAccessPolicy policyVersion={created['policyVersion']!r}, got {got['policyVersion']!r}"
    )
    assert _norm(got["policy"]) == json.loads(valid_policy), (
        f"expected GetAccessPolicy policy={valid_policy!r}, got {got['policy']!r}"
    )


def _short_name(ctx: Any, prefix: str) -> str:
    raw = ctx.unique_name(prefix + "-").lower()
    raw = re.sub(r"[^a-z0-9-]", "", raw)
    if not raw or not raw[0].isalpha():
        raw = "a" + raw
    raw = raw[:24].rstrip("-")
    while len(raw) < 3:
        raw += "0"
    return raw


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


def _norm(v: Any) -> Any:
    """The policy field round-trips as a parsed object on read, a JSON string on write."""
    return json.loads(v) if isinstance(v, str) else v


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
