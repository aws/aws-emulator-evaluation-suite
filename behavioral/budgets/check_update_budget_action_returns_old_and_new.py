"""update-budget-action-returns-old-and-new."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-budget-action-returns-old-and-new"
GROUP = "state"
SERVICES = ["budgets"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateBudgetAction returns both OldAction (pre-update) and NewAction (post-update) state."""
    budgets = ctx.client("budgets")
    account_id = _account_id(ctx)
    budget_name = ctx.unique_name("sim2real-budget-actupd-")
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
        Subscribers=[{"SubscriptionType": "EMAIL", "Address": "sim2real-budgets-actupd@example.com"}],
        ResourceTags=[{"Key": "sim2real-env", "Value": "behavioral-test"}],
    )
    action_id = resp["ActionId"]
    ctx.on_cleanup(
        lambda: budgets.delete_budget_action(AccountId=account_id, BudgetName=budget_name, ActionId=action_id)
    )

    update_resp = budgets.update_budget_action(
        AccountId=account_id,
        BudgetName=budget_name,
        ActionId=action_id,
        ApprovalModel="AUTOMATIC",
    )
    old_action = update_resp["OldAction"]
    new_action = update_resp["NewAction"]
    assert old_action["ApprovalModel"] == "MANUAL", (
        f"expected OldAction.ApprovalModel=MANUAL, got {old_action['ApprovalModel']!r}"
    )
    assert new_action["ApprovalModel"] == "AUTOMATIC", (
        f"expected NewAction.ApprovalModel=AUTOMATIC, got {new_action['ApprovalModel']!r}"
    )
    assert old_action["ActionId"] == action_id, (
        f"expected OldAction.ActionId={action_id!r}, got {old_action['ActionId']!r}"
    )
    assert new_action["ActionId"] == action_id, (
        f"expected NewAction.ActionId={action_id!r}, got {new_action['ActionId']!r}"
    )
    # Only the field named in the update request should differ between Old and New —
    # everything else the target reported must round-trip unchanged.
    assert old_action["ActionThreshold"] == new_action["ActionThreshold"], (
        f"expected ActionThreshold unchanged across update, "
        f"got old={old_action['ActionThreshold']!r} new={new_action['ActionThreshold']!r}"
    )

    described = budgets.describe_budget_action(
        AccountId=account_id, BudgetName=budget_name, ActionId=action_id
    )["Action"]
    assert described["ApprovalModel"] == "AUTOMATIC", (
        f"expected persisted ApprovalModel=AUTOMATIC on independent describe, "
        f"got {described['ApprovalModel']!r}"
    )


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
        ResourceTags=[{"Key": "sim2real-env", "Value": "behavioral-test"}],
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
        Tags=[{"Key": "sim2real-env", "Value": "behavioral-test"}],
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
