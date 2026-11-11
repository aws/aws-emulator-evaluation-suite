"""describe-budget-actions-for-account-and-budget-list-created-action."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-budget-actions-for-account-and-budget-list-created-action"
GROUP = "state"
SERVICES = ["budgets"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A newly created action shows up in both DescribeBudgetActionsForBudget and DescribeBudgetActionsForAccount."""
    budgets = ctx.client("budgets")
    account_id = _account_id(ctx)
    budget_name = ctx.unique_name("sim2real-budget-actlist-")
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
        Subscribers=[{"SubscriptionType": "EMAIL", "Address": "sim2real-budgets-actlist@example.com"}],
        ResourceTags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-budget-actlist"}],
    )
    action_id = resp["ActionId"]
    ctx.on_cleanup(
        lambda: budgets.delete_budget_action(AccountId=account_id, BudgetName=budget_name, ActionId=action_id)
    )

    for_budget = budgets.describe_budget_actions_for_budget(AccountId=account_id, BudgetName=budget_name)[
        "Actions"
    ]
    assert any(a["ActionId"] == action_id for a in for_budget), (
        f"expected action {action_id!r} in DescribeBudgetActionsForBudget, got "
        f"{[a['ActionId'] for a in for_budget]!r}"
    )

    found = False
    next_token = None
    for _ in range(20):
        kwargs = {"AccountId": account_id}
        if next_token:
            kwargs["NextToken"] = next_token
        page = budgets.describe_budget_actions_for_account(**kwargs)
        if any(a["ActionId"] == action_id for a in page["Actions"]):
            found = True
            break
        next_token = page.get("NextToken")
        if not next_token:
            break
    assert found, "created action was not found via DescribeBudgetActionsForAccount"


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _create_budget(budgets, account_id, name, amount="200.0"):
    budgets.create_budget(
        AccountId=account_id,
        Budget={
            "BudgetName": name,
            "BudgetLimit": {"Amount": amount, "Unit": "USD"},
            "TimeUnit": "MONTHLY",
            "BudgetType": "COST",
        },
        ResourceTags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-budget-actlist"}],
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-budgets-role"}],
    )
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
    # Newly created IAM roles/policies are eventually consistent: budgets.amazonaws.com
    # may not yet be able to assume the role (AccessDeniedException) or validate the
    # role (InvalidParameterException) for a short window after creation.
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
