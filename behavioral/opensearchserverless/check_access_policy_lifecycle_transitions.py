"""access-policy-lifecycle-transitions."""
from __future__ import annotations

import json
import re
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "access-policy-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["opensearchserverless"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AccessPolicy created, read, updated, then deleted with GetAccessPolicy 404 after."""
    aoss = ctx.client("opensearchserverless")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = _short_name(ctx, "sim2real-datapol")
    principal = f"arn:aws:iam::{account_id}:role/{name}-role"

    policy_v1 = json.dumps(
        [
            {
                "Rules": [
                    {
                        "ResourceType": "index",
                        "Resource": [f"index/{name}*/*"],
                        "Permission": ["aoss:ReadDocument"],
                    }
                ],
                "Principal": [principal],
            }
        ]
    )

    created = aoss.create_access_policy(
        type="data",
        name=name,
        description="sim2real behavioral access policy",
        policy=policy_v1,
    )["accessPolicyDetail"]
    version1 = created["policyVersion"]
    assert created["type"] == "data", f"expected type 'data', got {created['type']!r}"
    assert _norm(created["policy"]) == _norm(policy_v1), (
        f"created policy body diverged from the request: {created['policy']!r} "
        f"vs {policy_v1!r}"
    )

    def _cleanup() -> None:
        try:
            aoss.delete_access_policy(type="data", name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    got = aoss.get_access_policy(type="data", name=name)["accessPolicyDetail"]
    assert got["policyVersion"] == version1, (
        f"independent GetAccessPolicy read expected version {version1!r}, "
        f"got {got['policyVersion']!r}"
    )

    # representation consistency: ListAccessPolicies summary agrees with the GetAccessPolicy
    # detail on the overlapping fields (name/type/policyVersion), even though the summary
    # omits the policy document body itself
    summaries = {
        s["name"]: s
        for s in aoss.list_access_policies(type="data")["accessPolicySummaries"]
    }
    assert name in summaries, (
        f"{name!r} missing from ListAccessPolicies summaries {sorted(summaries)}"
    )
    assert summaries[name]["type"] == got["type"], (
        f"summary type {summaries[name]['type']!r} disagrees with detail type {got['type']!r}"
    )
    assert summaries[name]["policyVersion"] == got["policyVersion"], (
        f"summary version {summaries[name]['policyVersion']!r} disagrees with "
        f"detail version {got['policyVersion']!r}"
    )

    policy_v2 = json.dumps(
        [
            {
                "Rules": [
                    {
                        "ResourceType": "index",
                        "Resource": [f"index/{name}*/*"],
                        "Permission": ["aoss:*"],
                    }
                ],
                "Principal": [principal],
            }
        ]
    )
    updated = aoss.update_access_policy(
        type="data", name=name, policyVersion=version1, policy=policy_v2
    )["accessPolicyDetail"]
    version2 = updated["policyVersion"]
    assert version2 != version1, (
        f"UpdateAccessPolicy did not advance the version past {version1!r}"
    )
    assert _norm(updated["policy"]) == _norm(policy_v2), (
        f"updated policy body diverged from the request: {updated['policy']!r} "
        f"vs {policy_v2!r}"
    )

    aoss.delete_access_policy(type="data", name=name)

    code, message = _error(lambda: aoss.get_access_policy(type="data", name=name))
    assert code == "ResourceNotFoundException", (
        f"GetAccessPolicy on a deleted policy expected ResourceNotFoundException, "
        f"got {code!r}"
    )
    expected_message = f"Policy with name {name} and type data is not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # deletes prove gone AND unusable: a mutation on the now-dead id must also fail,
    # not just an independent read
    update_code, update_message = _error(
        lambda: aoss.update_access_policy(
            type="data", name=name, policyVersion=version2, policy=policy_v2
        )
    )
    assert update_code == "ResourceNotFoundException", (
        f"UpdateAccessPolicy on a deleted policy expected ResourceNotFoundException, "
        f"got {update_code!r}"
    )
    expected_update = f"Policy with name {name} and type data is not found"
    assert update_message == expected_update, f"expected message {expected_update!r}, got {update_message!r}"


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
