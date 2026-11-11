"""simulate-notaction-and-wildcard-matching."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "simulate-notaction-and-wildcard-matching"
GROUP = 'policy_simulation'
SERVICES = ['iam']

BUCKET_ARN = "arn:aws:s3:::sim2real-behav-simulated-bucket"
IN_SCOPE_OBJECT = BUCKET_ARN + "/team/report.csv"
OUT_OF_SCOPE_OBJECT = BUCKET_ARN + "/private/secrets.csv"

# Allow everything EXCEPT the iam namespace. NotAction inverts the match set.
ALLOW_NOTACTION_IAM = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "AllowAllButIam", "Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}
        ],
    }
)
# Allow all of s3 on the bucket, then explicitly deny everything OUTSIDE the /team/ prefix.
# NotResource inverts the resource match set on a Deny.
ALLOW_S3_DENY_NOTRESOURCE_TEAM_PREFIX = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowBucketObjects",
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": BUCKET_ARN + "/*",
            },
            {
                "Sid": "DenyOutsideTeamPrefix",
                "Effect": "Deny",
                "Action": "s3:*",
                "NotResource": BUCKET_ARN + "/team/*",
            },
        ],
    }
)
# Action wildcard on a prefix, resource wildcard on a key prefix.
ALLOW_S3_GET_STAR_ON_TEAM_PREFIX = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowGetStarOnTeamPrefix",
                "Effect": "Allow",
                "Action": "s3:Get*",
                "Resource": BUCKET_ARN + "/team/*",
            }
        ],
    }
)


def _simulate(iam, policy, actions, resource=None):
    """EvaluationResults for one SimulateCustomPolicy call.

    At most ONE ResourceArn is ever passed, so the response is unambiguously one
    EvaluationResult per action with EvalResourceName echoing that ARN. (The multi-resource
    ResourceSpecificResults shape is not asserted here.)
    """
    kwargs = {"PolicyInputList": [policy], "ActionNames": actions}
    if resource is not None:
        kwargs["ResourceArns"] = [resource]
    results = iam.simulate_custom_policy(**kwargs)["EvaluationResults"]
    assert len(results) == len(actions), (
        f"expected one EvaluationResult per action ({len(actions)}), got {results}"
    )
    return results


def _decision_for(iam, policy, action, resource):
    """(EvalDecision, EvalResourceName) for a single action against a single resource ARN."""
    result = _simulate(iam, policy, [action], resource)[0]
    return result["EvalDecision"], result.get("EvalResourceName")


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SimulateCustomPolicy evaluates NotAction, NotResource and wildcards exactly: NotAction allows
    only the complement, NotResource denies only the complement (EvalResourceName echoes the ARN),
    s3:Get* matches GetObject but not PutObject, and a team/* resource matches only that prefix."""
    iam = ctx.client("iam")

    # --- 1. NotAction: everything except iam:* is allowed; iam:* is not.
    notaction = {
        r["EvalActionName"]: r["EvalDecision"]
        for r in _simulate(iam, ALLOW_NOTACTION_IAM, ["s3:GetObject", "iam:CreateUser"])
    }
    assert notaction["s3:GetObject"] == "allowed", (
        "NotAction 'iam:*' must allow every action outside the iam namespace; s3:GetObject got "
        f"{notaction['s3:GetObject']!r}"
    )
    assert notaction["iam:CreateUser"] == "implicitDeny", (
        "NotAction 'iam:*' must NOT allow iam actions; iam:CreateUser got "
        f"{notaction['iam:CreateUser']!r} -- an emulator treating NotAction like Action, or ignoring "
        "it, is over-permissive here"
    )

    # --- 2. NotResource on a Deny: the complement of /team/* is denied, /team/* survives.
    in_scope_decision, in_scope_name = _decision_for(
        iam, ALLOW_S3_DENY_NOTRESOURCE_TEAM_PREFIX, "s3:GetObject", IN_SCOPE_OBJECT
    )
    assert in_scope_decision == "allowed", (
        f"{IN_SCOPE_OBJECT} is inside NotResource's exempt prefix so the Deny must not apply; got "
        f"{in_scope_decision!r}"
    )
    assert in_scope_name == IN_SCOPE_OBJECT, (
        f"EvalResourceName must echo the ARN supplied in ResourceArns; got {in_scope_name!r}"
    )
    out_scope_decision, out_scope_name = _decision_for(
        iam, ALLOW_S3_DENY_NOTRESOURCE_TEAM_PREFIX, "s3:GetObject", OUT_OF_SCOPE_OBJECT
    )
    assert out_scope_decision == "explicitDeny", (
        f"{OUT_OF_SCOPE_OBJECT} is outside NotResource's exempt prefix so the Deny must apply and "
        f"override the s3:* Allow; got {out_scope_decision!r}"
    )
    assert out_scope_name == OUT_OF_SCOPE_OBJECT, (
        f"EvalResourceName must echo the ARN supplied in ResourceArns; got {out_scope_name!r}"
    )

    # --- 3. Action wildcard: s3:Get* matches s3:GetObject, not s3:PutObject.
    action_wild = {
        r["EvalActionName"]: r["EvalDecision"]
        for r in _simulate(
            iam,
            ALLOW_S3_GET_STAR_ON_TEAM_PREFIX,
            ["s3:GetObject", "s3:PutObject"],
            IN_SCOPE_OBJECT,
        )
    }
    assert action_wild["s3:GetObject"] == "allowed", (
        f"'s3:Get*' must match s3:GetObject; got {action_wild['s3:GetObject']!r}"
    )
    assert action_wild["s3:PutObject"] == "implicitDeny", (
        "'s3:Get*' must NOT match s3:PutObject -- a matcher that treats any '*' as match-all is "
        f"over-permissive; got {action_wild['s3:PutObject']!r}"
    )

    # --- 4. Resource wildcard: the same allowed action is scoped to the /team/ key prefix.
    wild_hit, _ = _decision_for(
        iam, ALLOW_S3_GET_STAR_ON_TEAM_PREFIX, "s3:GetObject", IN_SCOPE_OBJECT
    )
    assert wild_hit == "allowed", (
        f"'{BUCKET_ARN}/team/*' must match {IN_SCOPE_OBJECT}; got {wild_hit!r}"
    )
    wild_miss, _ = _decision_for(
        iam, ALLOW_S3_GET_STAR_ON_TEAM_PREFIX, "s3:GetObject", OUT_OF_SCOPE_OBJECT
    )
    assert wild_miss == "implicitDeny", (
        f"'{BUCKET_ARN}/team/*' must NOT match {OUT_OF_SCOPE_OBJECT}; got {wild_miss!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
