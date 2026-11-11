"""execute-budget-action-wrong-state-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-budget-action-wrong-state-rejected"
GROUP = "overly-permissive"
SERVICES = ["budgets"]

# The limit is far above any account's spend, so the 80% ACTUAL threshold is never crossed and the
# action stays in STANDBY instead of moving to PENDING (awaiting approval) on an account that spends.
_BUDGET_LIMIT_USD = "1000000.0"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ExecuteBudgetAction(REVERSE_BUDGET_ACTION) on a STANDBY action (never executed) is rejected."""
    budgets = ctx.client("budgets")
    account_id = _account_id(ctx)
    budget_name = ctx.unique_name("sim2real-budget-actwrongstate-")
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
        Subscribers=[{"SubscriptionType": "EMAIL", "Address": "sim2real-budgets-actwrongstate@example.com"}],
    )
    action_id = resp["ActionId"]
    ctx.on_cleanup(
        lambda: budgets.delete_budget_action(AccountId=account_id, BudgetName=budget_name, ActionId=action_id)
    )

    # The action has just been created and is STANDBY, and has never been executed.
    # REVERSE_BUDGET_ACTION only makes sense for an action that has actually run, so
    # reversing a never-executed action must be rejected.
    error = _error(
        lambda: budgets.execute_budget_action(
            AccountId=account_id,
            BudgetName=budget_name,
            ActionId=action_id,
            ExecutionType="REVERSE_BUDGET_ACTION",
        )
    )
    assert error["Code"] == "ResourceLockedException", f"expected ResourceLockedException, got {error['Code']!r}"
    expected_message = "This method is not allowed during [ActionStatus: Standby]"
    assert error.get("Message") == expected_message, f"expected {expected_message!r}, got {error.get('Message')!r}"
    described = budgets.describe_budget_action(
        AccountId=account_id, BudgetName=budget_name, ActionId=action_id
    )["Action"]
    assert described["Status"] == "STANDBY", f"expected the action to remain STANDBY, got {described['Status']!r}"

    # Positive control: a normal write operation against the same action still succeeds.
    update_resp = budgets.update_budget_action(
        AccountId=account_id, BudgetName=budget_name, ActionId=action_id, ApprovalModel="AUTOMATIC"
    )
    assert update_resp["NewAction"]["ApprovalModel"] == "AUTOMATIC", (
        f"expected the positive-control update to take effect, got {update_resp['NewAction']['ApprovalModel']!r}"
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
        ResourceTags=[{"Key": "sim2real", "Value": CHECK}],
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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


def _error(fn):
    """Call fn(); return its ClientError's Error dict; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
