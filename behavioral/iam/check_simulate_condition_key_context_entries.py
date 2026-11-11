"""simulate-condition-key-context-entries."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "simulate-condition-key-context-entries"
GROUP = 'policy_simulation'
SERVICES = ['iam']

# Allow guarded by an IpAddress condition on aws:SourceIp. Resource is "*" and the simulation
# passes no ResourceArns, which is the documented situation in which unresolved condition keys are
# reported in MissingContextValues.
ALLOW_IF_SOURCE_IP = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowFromOfficeCidr",
                "Effect": "Allow",
                "Action": "s3:ListBucket",
                "Resource": "*",
                "Condition": {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}},
            }
        ],
    }
)
IN_CIDR = "203.0.113.5"
OUT_OF_CIDR = "198.51.100.5"


def _result(iam, context_entries=None):
    """The single EvaluationResult for s3:ListBucket under ALLOW_IF_SOURCE_IP."""
    kwargs = {
        "PolicyInputList": [ALLOW_IF_SOURCE_IP],
        "ActionNames": ["s3:ListBucket"],
    }
    if context_entries is not None:
        kwargs["ContextEntries"] = context_entries
    results = iam.simulate_custom_policy(**kwargs)["EvaluationResults"]
    assert len(results) == 1, f"expected exactly one EvaluationResult, got {results}"
    return results[0]


@tags("axis:happy-path", "cap:c7", "plane:control")
def run(ctx) -> None:
    """SimulateCustomPolicy evaluates an aws:SourceIp Condition: withheld, the key is in
    MissingContextValues and the decision implicitDeny; a satisfying value is 'allowed' via
    PolicyInputList.1; a violating value is implicitDeny."""
    iam = ctx.client("iam")

    # --- 1. Key not supplied: reported as missing, and the guarded Allow does not fire.
    missing = _result(iam)
    assert "aws:SourceIp" in missing.get("MissingContextValues", []), (
        "aws:SourceIp is referenced by the policy Condition but not supplied, so it must appear in "
        f"MissingContextValues; got {missing.get('MissingContextValues')!r}"
    )
    assert missing["EvalDecision"] == "implicitDeny", (
        "an Allow whose Condition cannot be evaluated must not grant; expected 'implicitDeny', got "
        f"{missing['EvalDecision']!r}"
    )

    # --- 2. Satisfying value supplied: the Allow fires, nothing is missing any more.
    inside = _result(
        iam,
        [
            {
                "ContextKeyName": "aws:SourceIp",
                "ContextKeyValues": [IN_CIDR],
                "ContextKeyType": "ip",
            }
        ],
    )
    assert inside["EvalDecision"] == "allowed", (
        f"{IN_CIDR} is inside 203.0.113.0/24 so the conditional Allow must fire; got "
        f"{inside['EvalDecision']!r}"
    )
    assert inside.get("MissingContextValues", []) == [], (
        "aws:SourceIp was supplied, so MissingContextValues must be empty; got "
        f"{inside.get('MissingContextValues')!r}"
    )
    matched_sources = sorted({s["SourcePolicyId"] for s in inside.get("MatchedStatements", [])})
    assert matched_sources == ["PolicyInputList.1"], (
        "the granting statement must be attributed to the supplied input policy; got "
        f"{matched_sources} from {inside.get('MatchedStatements')}"
    )

    # --- 3. Violating value supplied: the key is known, the condition simply does not match.
    outside = _result(
        iam,
        [
            {
                "ContextKeyName": "aws:SourceIp",
                "ContextKeyValues": [OUT_OF_CIDR],
                "ContextKeyType": "ip",
            }
        ],
    )
    assert outside["EvalDecision"] == "implicitDeny", (
        f"{OUT_OF_CIDR} is outside 203.0.113.0/24 so the conditional Allow must NOT fire; got "
        f"{outside['EvalDecision']!r}"
    )
    assert outside.get("MissingContextValues", []) == [], (
        "aws:SourceIp WAS supplied (it just did not match), so MissingContextValues must be empty; "
        f"got {outside.get('MissingContextValues')!r}"
    )
    assert outside.get("MatchedStatements", []) == [], (
        "a non-matching condition must match no statement at all; got "
        f"{outside.get('MatchedStatements')!r}"
    )

    # --- Control: the same three-way discrimination must not be an artifact of the action name.
    # An action the policy never mentions is implicitDeny even with a satisfying context value.
    unrelated = iam.simulate_custom_policy(
        PolicyInputList=[ALLOW_IF_SOURCE_IP],
        ActionNames=["s3:DeleteBucket"],
        ContextEntries=[
            {
                "ContextKeyName": "aws:SourceIp",
                "ContextKeyValues": [IN_CIDR],
                "ContextKeyType": "ip",
            }
        ],
    )["EvaluationResults"][0]
    assert unrelated["EvalDecision"] == "implicitDeny", (
        "s3:DeleteBucket is not in the policy's Action, so a satisfied Condition must not grant it; "
        f"got {unrelated['EvalDecision']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
