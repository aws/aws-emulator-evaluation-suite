"""create-access-policy-idempotent-clienttoken."""
from __future__ import annotations

import json
import uuid
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-access-policy-idempotent-clienttoken"
GROUP = "ordering"
SERVICES = ["opensearchserverless"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A repeat CreateAccessPolicy with the same clientToken keeps the policy version, and after deletion both
    GetAccessPolicy and a second delete fail with ResourceNotFoundException and their exact messages.
    """
    client = ctx.client("opensearchserverless")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real-ap-")
    token = str(uuid.uuid4())
    policy_doc = json.dumps(
        [
            {
                "Rules": [
                    {
                        "ResourceType": "collection",
                        "Resource": [f"collection/{name}"],
                        "Permission": ["aoss:DescribeCollectionItems"],
                    }
                ],
                "Principal": [f"arn:aws:iam::{account_id}:role/{name}-role"],
            }
        ]
    )

    resp1 = client.create_access_policy(
        type="data", name=name, policy=policy_doc, clientToken=token
    )
    detail1 = resp1["accessPolicyDetail"]

    def _cleanup() -> None:
        try:
            client.delete_access_policy(type="data", name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    resp2 = client.create_access_policy(
        type="data", name=name, policy=policy_doc, clientToken=token
    )
    detail2 = resp2["accessPolicyDetail"]

    assert detail2["policyVersion"] == detail1["policyVersion"], (
        "repeating CreateAccessPolicy with the same clientToken should not create a "
        f"duplicate/new version, got {detail1['policyVersion']!r} then {detail2['policyVersion']!r}"
    )

    got = client.get_access_policy(type="data", name=name)["accessPolicyDetail"]
    assert got["policyVersion"] == detail1["policyVersion"], (
        f"expected the independently-read policyVersion to stay {detail1['policyVersion']!r}, "
        f"got {got['policyVersion']!r}"
    )

    # now genuinely delete the policy, and prove the delete: an independent read must see it
    # gone, and a second delete must fail not-found.
    client.delete_access_policy(type="data", name=name)
    gone_code, gone_message = _error(lambda: client.get_access_policy(type="data", name=name))
    assert gone_code == "ResourceNotFoundException", (
        f"expected the deleted policy to read back ResourceNotFoundException, got {gone_code!r}"
    )
    expected_gone = f"Policy with name {name} and type data is not found"
    assert gone_message == expected_gone, f"expected message {expected_gone!r}, got {gone_message!r}"
    redelete_code, redelete_message = _error(lambda: client.delete_access_policy(type="data", name=name))
    assert redelete_code == "ResourceNotFoundException", (
        f"expected a second delete of the now-dead policy to fail the same way, got {redelete_code!r}"
    )
    expected_redelete = f"Policy with name {name} and type data is not found"
    assert redelete_message == expected_redelete, (
        f"expected message {expected_redelete!r}, got {redelete_message!r}"
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
