"""delete-nonexistent-access-policy-resourcenotfound."""
from __future__ import annotations

import json
import re
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-nonexistent-access-policy-resourcenotfound"
GROUP = "error-semantics"
SERVICES = ["opensearchserverless"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteAccessPolicy for an unknown name fails with ResourceNotFoundException and its exact message and
    leaves a real policy readable; that policy then deletes, and a read and a second delete fail with
    ResourceNotFoundException.
    """
    aoss = ctx.client("opensearchserverless")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    real_name = _short_name(ctx, "sim2real-delap-real")
    missing_name = _short_name(ctx, "sim2real-delap-miss")
    principal = f"arn:aws:iam::{account_id}:role/{real_name}-role"

    policy = json.dumps(
        [
            {
                "Rules": [
                    {
                        "ResourceType": "index",
                        "Resource": [f"index/{real_name}*/*"],
                        "Permission": ["aoss:ReadDocument"],
                    }
                ],
                "Principal": [principal],
            }
        ]
    )
    created = aoss.create_access_policy(type="data", name=real_name, policy=policy)[
        "accessPolicyDetail"
    ]
    assert created["name"] == real_name

    def _cleanup() -> None:
        try:
            aoss.delete_access_policy(type="data", name=real_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    # negative: a name that was never created is rejected with ResourceNotFoundException
    code, message = _error(lambda: aoss.delete_access_policy(type="data", name=missing_name))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException deleting a never-created access policy, got {code!r}"
    )
    expected_message = f"Policy with name {missing_name} and type data is not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # positive control (unaffected leg): the real policy is completely unaffected by the failed
    # delete attempt above
    got = aoss.get_access_policy(type="data", name=real_name)["accessPolicyDetail"]
    assert got["name"] == real_name
    assert got["policyVersion"] == created["policyVersion"]

    # positive control (operation-under-test leg): DeleteAccessPolicy itself must succeed against
    # a real, existing policy. Without this, a target whose DeleteAccessPolicy unconditionally
    # throws ResourceNotFoundException -- never actually deleting anything -- would pass the
    # negative above for the wrong reason.
    aoss.delete_access_policy(type="data", name=real_name)

    # deletes prove gone and unusable: an independent read of the now-deleted policy returns the
    # specific not-found code, and a second delete of the same dead name fails not-found rather
    # than silently succeeding.
    gone_code, gone_message = _error(lambda: aoss.get_access_policy(type="data", name=real_name))
    assert gone_code == "ResourceNotFoundException", (
        f"expected the deleted policy to be gone via an independent read, got {gone_code!r}"
    )
    expected_gone = f"Policy with name {real_name} and type data is not found"
    assert gone_message == expected_gone, f"expected message {expected_gone!r}, got {gone_message!r}"
    double_delete_code, double_delete_message = _error(
        lambda: aoss.delete_access_policy(type="data", name=real_name)
    )
    assert double_delete_code == "ResourceNotFoundException", (
        f"expected a second delete of the now-gone policy to fail not-found, got {double_delete_code!r}"
    )
    expected_double = f"Policy with name {real_name} and type data is not found"
    assert double_delete_message == expected_double, (
        f"expected message {expected_double!r}, got {double_delete_message!r}"
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
