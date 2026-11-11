"""security-policy-lifecycle-transitions."""
from __future__ import annotations

import json
import re
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "security-policy-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["opensearchserverless"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SecurityPolicy created, read, updated, then deleted and no longer retrievable."""
    aoss = ctx.client("opensearchserverless")
    name = _short_name(ctx, "sim2real-netpol")

    policy_v1 = json.dumps(
        [
            {
                "Rules": [{"ResourceType": "collection", "Resource": [f"collection/{name}*"]}],
                "AllowFromPublic": False,
                "SourceServices": ["bedrock.amazonaws.com"],
            }
        ]
    )

    created = aoss.create_security_policy(
        type="network",
        name=name,
        description="sim2real behavioral network policy",
        policy=policy_v1,
    )["securityPolicyDetail"]
    version1 = created["policyVersion"]
    assert created["type"] == "network", f"expected type 'network', got {created['type']!r}"
    assert _norm(created["policy"]) == _norm(policy_v1), (
        f"CreateSecurityPolicy echoed a different policy body: "
        f"expected {_norm(policy_v1)!r}, got {_norm(created['policy'])!r}"
    )

    def _cleanup() -> None:
        try:
            aoss.delete_security_policy(type="network", name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    got = aoss.get_security_policy(type="network", name=name)["securityPolicyDetail"]
    assert got["policyVersion"] == version1, (
        f"GetSecurityPolicy returned version {got['policyVersion']!r}, expected the "
        f"just-created version {version1!r}"
    )
    assert _norm(got["policy"]) == _norm(policy_v1), (
        f"GetSecurityPolicy body diverged from what was created: "
        f"expected {_norm(policy_v1)!r}, got {_norm(got['policy'])!r}"
    )

    # representation consistency: ListSecurityPolicies summary agrees with the
    # GetSecurityPolicy detail on the overlapping fields, even though the summary
    # omits the policy document body itself
    summaries = {
        s["name"]: s
        for s in aoss.list_security_policies(type="network")["securityPolicySummaries"]
    }
    assert name in summaries, f"{name!r} missing from ListSecurityPolicies(type=network)"
    assert summaries[name]["type"] == got["type"], (
        f"ListSecurityPolicies type {summaries[name]['type']!r} disagrees with "
        f"GetSecurityPolicy type {got['type']!r}"
    )
    assert summaries[name]["policyVersion"] == got["policyVersion"], (
        f"ListSecurityPolicies version {summaries[name]['policyVersion']!r} disagrees with "
        f"GetSecurityPolicy version {got['policyVersion']!r}"
    )

    policy_v2 = json.dumps(
        [
            {
                "Rules": [
                    {"ResourceType": "collection", "Resource": [f"collection/{name}*"]},
                    {"ResourceType": "dashboard", "Resource": [f"collection/{name}*"]},
                ],
                "AllowFromPublic": False,
                "SourceServices": ["bedrock.amazonaws.com"],
            }
        ]
    )
    updated = aoss.update_security_policy(
        type="network", name=name, policyVersion=version1, policy=policy_v2
    )["securityPolicyDetail"]
    assert updated["policyVersion"] != version1, (
        f"UpdateSecurityPolicy kept version {version1!r} after a real content change"
    )
    assert _norm(updated["policy"]) == _norm(policy_v2), (
        f"UpdateSecurityPolicy echoed a different body: "
        f"expected {_norm(policy_v2)!r}, got {_norm(updated['policy'])!r}"
    )
    version2 = updated["policyVersion"]

    got2 = aoss.get_security_policy(type="network", name=name)["securityPolicyDetail"]
    assert _norm(got2["policy"]) == _norm(policy_v2), (
        f"GetSecurityPolicy after update still shows the old body: "
        f"expected {_norm(policy_v2)!r}, got {_norm(got2['policy'])!r}"
    )

    aoss.delete_security_policy(type="network", name=name)

    code, message = _error(lambda: aoss.get_security_policy(type="network", name=name))
    assert code == "ResourceNotFoundException", (
        f"GetSecurityPolicy after delete should be ResourceNotFoundException, got {code!r}"
    )
    expected_message = f"Policy with name {name} and type network is not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # a mutation on the dead identifier must fail the same way an independent read does
    mutate_code, mutate_message = _error(
        lambda: aoss.update_security_policy(
            type="network", name=name, policyVersion=version2, policy=policy_v2
        )
    )
    assert mutate_code == "ResourceNotFoundException", (
        f"UpdateSecurityPolicy on a deleted policy should be ResourceNotFoundException, "
        f"got {mutate_code!r}"
    )
    expected_mutate = f"Policy with name {name} and type network is not found"
    assert mutate_message == expected_mutate, f"expected message {expected_mutate!r}, got {mutate_message!r}"

    # the identifier is reusable: creating a fresh policy under the same name succeeds
    recreated = aoss.create_security_policy(
        type="network",
        name=name,
        description="sim2real behavioral network policy (recreated)",
        policy=policy_v1,
    )["securityPolicyDetail"]
    assert recreated["type"] == "network", (
        f"recreating {name!r} after delete should succeed with type 'network', "
        f"got {recreated['type']!r}"
    )
    assert _norm(recreated["policy"]) == _norm(policy_v1), (
        f"recreated policy body diverged: expected {_norm(policy_v1)!r}, "
        f"got {_norm(recreated['policy'])!r}"
    )


def _short_name(ctx: Any, prefix: str) -> str:
    raw = ctx.unique_name(prefix + "-").lower()
    raw = re.sub(r"[^a-z0-9-]", "", raw)
    if not raw or not raw[0].isalpha():
        raw = "a" + raw
    raw = raw[:32].rstrip("-")
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
