"""delete-budget-action-removes-resource."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-budget-action-removes-resource"
GROUP = "state"
SERVICES = ["budgets"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteBudgetAction removes the action; a subsequent DescribeBudgetAction returns NotFoundException."""
    budgets = ctx.client("budgets")
    account_id = _account_id(ctx)
    budget_name = ctx.unique_name("sim2real-budget-actdel-")
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
        Subscribers=[{"SubscriptionType": "EMAIL", "Address": "sim2real-budgets-actdel@example.com"}],
        ResourceTags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-budget-actdel"}],
    )
    action_id = resp["ActionId"]

    budgets.delete_budget_action(AccountId=account_id, BudgetName=budget_name, ActionId=action_id)

    expected_message = f"Action for [AccountId: {account_id}, ActionId: {action_id}] is not found!"
    error = _client_error(
        lambda: budgets.describe_budget_action(AccountId=account_id, BudgetName=budget_name, ActionId=action_id)
    )
    assert error["Code"] == "NotFoundException", (
        f"expected DescribeBudgetAction on a deleted action to be NotFoundException, got {error['Code']!r}"
    )
    assert error.get("Message") == expected_message, f"expected {expected_message!r}, got {error.get('Message')!r}"

    # A mutation on the dead id must also fail, not just a read.
    exec_error = _client_error(
        lambda: budgets.execute_budget_action(
            AccountId=account_id,
            BudgetName=budget_name,
            ActionId=action_id,
            ExecutionType="APPROVE_BUDGET_ACTION",
        )
    )
    assert exec_error["Code"] == "NotFoundException", (
        f"expected ExecuteBudgetAction on a deleted action to be NotFoundException, got {exec_error['Code']!r}"
    )
    assert exec_error.get("Message") == expected_message, (
        f"expected {expected_message!r}, got {exec_error.get('Message')!r}"
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
        ResourceTags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-budget-actdel"}],
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


def _client_error(fn):
    """Call fn(); return the ClientError's Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
