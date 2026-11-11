"""iam-simulate-principal-policy."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "iam-simulate-principal-policy"
GROUP = 'policy_simulation'
SERVICES = ['iam']
#: The default service-class budget for the simulator's convergence; the harness deadline bounds the run.
POLL_BUDGET_S = 300.0

@tags("axis:happy-path", "cap:c7", "plane:control")
def run(ctx) -> None:
    """SimulatePrincipalPolicy tracks the principal's policies: attached allow -> 'allowed', an unlisted
    action -> 'implicitDeny', an inline deny -> 'explicitDeny' naming that policy, removing the deny
    -> 'allowed', detaching the allow -> 'implicitDeny'. Advisory decisions only, no enforcement."""
    iam = ctx.client("iam")
    user = ctx.unique_name("sim2real-behav-user-")
    iam.create_user(UserName=user, Path="/", Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda n=user: iam.delete_user(UserName=n))
    user_arn = iam.get_user(UserName=user)["User"]["Arn"]

    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
            ],
        }
    )
    policy_arn = iam.create_policy(
        PolicyName=ctx.unique_name("sim2real-behav-pol-"),
        PolicyDocument=policy_doc,
        Path="/",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda a=policy_arn: iam.delete_policy(PolicyArn=a))
    iam.attach_user_policy(UserName=user, PolicyArn=policy_arn)
    ctx.on_cleanup(
        lambda u=user, p=policy_arn: _quiet(lambda: iam.detach_user_policy(UserName=u, PolicyArn=p))
    )

    def evaluate(action: str) -> dict:
        resp = iam.simulate_principal_policy(
            PolicySourceArn=user_arn, ActionNames=[action]
        )
        return resp["EvaluationResults"][0]

    def converge(action: str, want: str) -> dict:
        """Policy changes reach the simulator eventually; poll (bounded) for the decision."""
        deadline = time.monotonic() + POLL_BUDGET_S
        while True:
            result = evaluate(action)
            if result["EvalDecision"] == want:
                return result
            if time.monotonic() > deadline:
                raise AssertionError(f"expected {want} for {action}, still {result['EvalDecision']!r}")
            time.sleep(3)

    converge("s3:GetObject", "allowed")

    denied = evaluate("s3:PutObject")["EvalDecision"]
    assert denied == "implicitDeny", f"expected implicitDeny for the unlisted s3:PutObject, got {denied!r}"

    # An inline explicit Deny overrides the attached Allow, and the simulator names it.
    deny_name = ctx.unique_name("sim2real-behav-deny-")
    iam.put_user_policy(
        UserName=user,
        PolicyName=deny_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": "s3:GetObject", "Resource": "*"}],
        }),
    )
    ctx.on_cleanup(lambda u=user, n=deny_name: _quiet(lambda: iam.delete_user_policy(UserName=u, PolicyName=n)))
    result = converge("s3:GetObject", "explicitDeny")
    # SimulatePrincipalPolicy reports an inline user policy as SourcePolicyId user_<user>_<policy>.
    sources = [m.get("SourcePolicyId") for m in result.get("MatchedStatements", [])]
    assert sources == [f"user_{user}_{deny_name}"], (
        f"expected exactly one matched statement from the inline deny policy "
        f"{f'user_{user}_{deny_name}'!r}, got {sources!r}"
    )

    # Removing the deny restores the allow; detaching the allow leaves an implicit deny.
    iam.delete_user_policy(UserName=user, PolicyName=deny_name)
    converge("s3:GetObject", "allowed")
    iam.detach_user_policy(UserName=user, PolicyArn=policy_arn)
    converge("s3:GetObject", "implicitDeny")


def _quiet(fn):
    """Teardown call that tolerates the resource already being gone (the body removes it)."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
