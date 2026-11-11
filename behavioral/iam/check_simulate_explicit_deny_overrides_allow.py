"""simulate-explicit-deny-overrides-allow."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "simulate-explicit-deny-overrides-allow"
GROUP = 'policy_simulation'
SERVICES = ['iam']

# Two ad-hoc identity policies handed to the simulator as PolicyInputList.1 and .2.
# Deny must win over Allow for the one overlapping action, and per the API contract the
# deny statement must be the ONLY entry in MatchedStatements for that action.
ALLOW_ALL_S3 = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "AllowAllS3", "Effect": "Allow", "Action": "s3:*", "Resource": "*"}
        ],
    }
)
DENY_DELETE_OBJECT = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyDelete",
                "Effect": "Deny",
                "Action": "s3:DeleteObject",
                "Resource": "*",
            }
        ],
    }
)


def _decisions(iam, policies, actions):
    """{action: (EvalDecision, MatchedStatements)} for one SimulateCustomPolicy call."""
    resp = iam.simulate_custom_policy(PolicyInputList=policies, ActionNames=actions)
    results = resp["EvaluationResults"]
    assert len(results) == len(actions), (
        f"expected one EvaluationResult per action ({len(actions)}), got {len(results)}: {results}"
    )
    return {r["EvalActionName"]: (r["EvalDecision"], r.get("MatchedStatements", [])) for r in results}


@tags("axis:happy-path", "cap:c7", "plane:control")
def run(ctx) -> None:
    """In SimulateCustomPolicy an explicit Deny beats an Allow: s3:DeleteObject is 'explicitDeny'
    with the Deny statement (PolicyInputList.2, 'IAM Policy') as the sole MatchedStatements entry,
    and with the Deny input removed the same action is 'allowed'."""
    iam = ctx.client("iam")
    actions = ["s3:GetObject", "s3:DeleteObject"]

    # --- Deny + Allow together: deny wins for the overlapping action only.
    both = _decisions(iam, [ALLOW_ALL_S3, DENY_DELETE_OBJECT], actions)

    get_decision, get_matched = both["s3:GetObject"]
    assert get_decision == "allowed", (
        f"s3:GetObject is allowed by PolicyInputList.1 and denied by nothing; "
        f"expected 'allowed', got {get_decision!r}"
    )
    get_sources = sorted({s["SourcePolicyId"] for s in get_matched})
    assert get_sources == ["PolicyInputList.1"], (
        f"s3:GetObject must be attributed to the allow input only; got {get_sources} "
        f"from {get_matched}"
    )

    del_decision, del_matched = both["s3:DeleteObject"]
    assert del_decision == "explicitDeny", (
        f"a Deny statement on s3:DeleteObject must override the s3:* Allow; "
        f"expected 'explicitDeny', got {del_decision!r}"
    )
    assert len(del_matched) == 1, (
        "the API contract states the deny statement is the only entry included in the result; "
        f"got {len(del_matched)} MatchedStatements: {del_matched}"
    )
    assert del_matched[0]["SourcePolicyId"] == "PolicyInputList.2", (
        "the matched statement must be attributed to the DENY input (PolicyInputList.2), got "
        f"{del_matched[0]['SourcePolicyId']!r}"
    )
    assert del_matched[0]["SourcePolicyType"] == "IAM Policy", (
        f"expected SourcePolicyType 'IAM Policy', got {del_matched[0].get('SourcePolicyType')!r}"
    )

    # --- Effect absent / control: without the Deny input the same action is allowed, proving the
    # explicitDeny above came from the Deny statement and not from a broken allow path.
    allow_only = _decisions(iam, [ALLOW_ALL_S3], actions)
    assert allow_only["s3:DeleteObject"][0] == "allowed", (
        "with the Deny input removed, s3:* must allow s3:DeleteObject; got "
        f"{allow_only['s3:DeleteObject'][0]!r}"
    )
    assert allow_only["s3:GetObject"][0] == "allowed", (
        f"s3:* must allow s3:GetObject; got {allow_only['s3:GetObject'][0]!r}"
    )

    # --- The deny is scoped to the action it names: a third s3 action stays allowed alongside it.
    scoped = _decisions(iam, [ALLOW_ALL_S3, DENY_DELETE_OBJECT], ["s3:PutObject"])
    assert scoped["s3:PutObject"][0] == "allowed", (
        "the Deny statement names only s3:DeleteObject, so s3:PutObject must remain allowed; got "
        f"{scoped['s3:PutObject'][0]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
