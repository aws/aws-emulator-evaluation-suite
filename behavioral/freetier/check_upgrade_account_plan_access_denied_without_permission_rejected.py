"""upgrade-account-plan-access-denied-without-permission-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "upgrade-account-plan-access-denied-without-permission-rejected"
GROUP = "overly-permissive"
SERVICES = ["freetier"]


@tags("axis:happy-path", "cap:c7", "plane:control")
def run(ctx) -> None:
    """With an inline Deny of freetier:UpgradeAccountPlan on a role, SimulatePrincipalPolicy returns explicitDeny
    for that action and allowed for GetAccountPlanState, which still answers the caller; the irreversible upgrade
    itself is never called."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    identity = sts.get_caller_identity()
    # The Deny goes on a role this check creates, so the calling identity's own policies stay untouched; the
    # simulator evaluates the role's policies without the role ever being assumed.
    policy_source_arn = _scoped_role(ctx, iam, identity)

    sim = _simulate_with_retry(
        iam, policy_source_arn=policy_source_arn, action_names=["freetier:UpgradeAccountPlan"]
    )
    result = sim["EvaluationResults"][0]
    assert result["EvalDecision"] == "explicitDeny", result["EvalDecision"]

    # Positive control: the deny statement names ONLY UpgradeAccountPlan, so the role's allowed sibling
    # action GetAccountPlanState stays allowed for the same principal.
    control_sim = iam.simulate_principal_policy(
        PolicySourceArn=policy_source_arn, ActionNames=["freetier:GetAccountPlanState"]
    )
    control_decision = control_sim["EvaluationResults"][0]["EvalDecision"]
    assert control_decision == "allowed", control_decision

    # Real-call positive control: the caller's own client reaches the Free Tier API, so the explicitDeny
    # verdict above concerns that one action.
    freetier = ctx.client("freetier")
    try:
        state = freetier.get_account_plan_state()
        assert state["accountPlanType"] in ("FREE", "PAID"), state
    except ClientError as err:
        assert err.response["Error"]["Code"] == "ResourceNotFoundException", err.response["Error"]
        assert err.response["Error"]["Message"] == (
            f"Missing data for account: {identity['Account']}"
        ), err.response["Error"]["Message"]


def _simulate_with_retry(iam, *, policy_source_arn: str, action_names: list[str]):
    """IAM policy propagation to the simulator can lag by a few seconds after put_*_policy;
    poll until the simulator reflects the just-attached inline Deny (a just-created role can briefly
    answer NoSuchEntity)."""
    deadline = time.monotonic() + 30.0
    last = None
    while time.monotonic() < deadline:
        try:
            last = iam.simulate_principal_policy(PolicySourceArn=policy_source_arn, ActionNames=action_names)
        except ClientError as err:
            if err.response["Error"]["Code"] != "NoSuchEntity" or time.monotonic() >= deadline - 2.0:
                raise
            time.sleep(2.0)
            continue
        if last["EvaluationResults"][0]["EvalDecision"] == "explicitDeny":
            return last
        time.sleep(2.0)
    return last


# budget.cleanup_timeout for behavioral/freetier, one deadline shared by every teardown of a run.
_TEARDOWN_RETRY_S = 60.0
_POLICY_NAME = "sim2real-behav-freetier-deny-upgrade-account-plan"


def _scoped_role(ctx, iam, identity) -> str:
    """Create a role only the calling session may assume, allowed GetAccountPlanState and denied
    UpgradeAccountPlan; register its deletion and return its ARN."""
    name = ctx.unique_name("sim2real-freetier-upgrade-deny-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{identity['Account']}:root"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"aws:userid": identity["UserId"]}},
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    teardown_deadline: dict[str, float] = {}
    ctx.on_cleanup(lambda: _delete_role(iam, name, teardown_deadline))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "freetier:GetAccountPlanState", "Resource": "*"},
            {"Effect": "Deny", "Action": "freetier:UpgradeAccountPlan", "Resource": "*"},
        ],
    }
    iam.put_role_policy(RoleName=name, PolicyName=_POLICY_NAME, PolicyDocument=json.dumps(policy_doc))
    return role_arn


def _delete_role(iam, name: str, teardown_deadline: dict[str, float]) -> None:
    """Delete the role's inline policy and the role, then wait until GetRole answers NoSuchEntity;
    retry DeleteConflict every 2 s to the shared cleanup deadline and raise everything else."""
    deadline = teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_RETRY_S - 10.0)
    try:
        iam.delete_role_policy(RoleName=name, PolicyName=_POLICY_NAME)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchEntity":
            raise
    while True:
        try:
            iam.delete_role(RoleName=name)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "NoSuchEntity":
                break
            if code != "DeleteConflict" or time.monotonic() >= deadline:
                raise
            time.sleep(2.0)
            continue
        break
    while True:
        try:
            iam.get_role(RoleName=name)
        except ClientError as err:
            if err.response["Error"]["Code"] == "NoSuchEntity":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"role {name} still listed after DeleteRole")
        time.sleep(2.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


