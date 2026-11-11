"""create-budget-action-starts-standby."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-budget-action-starts-standby"
GROUP = "state"
SERVICES = ["budgets"]

# The limit is far above any account's spend, so the 80% ACTUAL threshold is never crossed and the
# action stays in STANDBY instead of moving to PENDING (awaiting approval) on an account that spends.
_BUDGET_LIMIT_USD = "1000000.0"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A freshly created budget action whose threshold the budget's spend has not crossed starts in
    ActionStatus STANDBY, not PENDING or any executed state, and round-trips its approval model and
    action type."""
    budgets = ctx.client("budgets")
    account_id = _account_id(ctx)
    budget_name = ctx.unique_name("sim2real-budget-actstandby-")
    _create_budget(budgets, account_id, budget_name)
    ctx.on_cleanup(lambda: budgets.delete_budget(AccountId=account_id, BudgetName=budget_name))

    role_name, role_arn = _create_execution_role(ctx)
    resp = _create_action_with_retry(
        ctx,
        budgets,
        AccountId=account_id,
        BudgetName=budget_name,
        NotificationType="ACTUAL",
        ActionType="APPLY_IAM_POLICY",
        ActionThreshold={"ActionThresholdValue": 80.0, "ActionThresholdType": "PERCENTAGE"},
        Definition={"IamActionDefinition": {"PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess", "Roles": [role_name]}},
        ExecutionRoleArn=role_arn,
        ApprovalModel="MANUAL",
        Subscribers=[{"SubscriptionType": "EMAIL", "Address": "sim2real-budgets-action@example.com"}],
    )
    action_id = resp["ActionId"]
    ctx.on_cleanup(
        lambda: budgets.delete_budget_action(AccountId=account_id, BudgetName=budget_name, ActionId=action_id)
    )

    described = budgets.describe_budget_action(
        AccountId=account_id, BudgetName=budget_name, ActionId=action_id
    )["Action"]
    assert described["Status"] == "STANDBY", (
        f"expected a freshly created action under an uncrossed threshold to be STANDBY, "
        f"got {described['Status']!r}"
    )
    assert described["ApprovalModel"] == "MANUAL", (
        f"expected ApprovalModel to round-trip as MANUAL, got {described['ApprovalModel']!r}"
    )
    assert described["ActionType"] == "APPLY_IAM_POLICY", (
        f"expected ActionType to round-trip as APPLY_IAM_POLICY, got {described['ActionType']!r}"
    )


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _create_budget(budgets, account_id, name, amount=_BUDGET_LIMIT_USD):
    budgets.create_budget(
        AccountId=account_id,
        Budget={
            "BudgetName": name,
            "BudgetLimit": {"Amount": amount, "Unit": "USD"},
            "TimeUnit": "MONTHLY",
            "BudgetType": "COST",
        },
    )


def _create_execution_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-budgets-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "budgets.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    permissions_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "iam:AttachGroupPolicy",
                    "iam:AttachRolePolicy",
                    "iam:AttachUserPolicy",
                    "iam:DetachGroupPolicy",
                    "iam:DetachRolePolicy",
                    "iam:DetachUserPolicy",
                ],
                "Resource": "*",
            }
        ],
    }
    policy_name = ctx.unique_name("sim2real-budgets-policy-")
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(permissions_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_name, role_arn


def _create_action_with_retry(ctx, budgets, timeout_s=90.0, **kwargs):
    # Newly created IAM roles/policies are eventually consistent (see IAM docs); retry
    # until the execution role becomes assumable/usable by the budgets service.
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return budgets.create_budget_action(**kwargs)
        except ClientError as err:
            if err.response["Error"]["Code"] not in ("InvalidParameterException", "AccessDeniedException"):
                raise
            last_err = err
            time.sleep(3)
    raise last_err


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
