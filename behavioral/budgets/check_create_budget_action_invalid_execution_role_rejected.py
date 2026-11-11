"""create-budget-action-invalid-execution-role-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-budget-action-invalid-execution-role-rejected"
GROUP = "overly-permissive"
SERVICES = ["budgets"]

# The limit is far above any account's spend, so the 80% ACTUAL threshold is never crossed and the
# action stays in STANDBY instead of moving to PENDING (awaiting approval) on an account that spends.
_BUDGET_LIMIT_USD = "1000000.0"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateBudgetAction rejects a well-formed but non-existent/non-assumable ExecutionRoleArn."""
    budgets = ctx.client("budgets")
    account_id = _account_id(ctx)
    budget_name = ctx.unique_name("sim2real-budget-badrole-")
    budgets.create_budget(
        AccountId=account_id,
        Budget={
            "BudgetName": budget_name,
            "BudgetLimit": {"Amount": _BUDGET_LIMIT_USD, "Unit": "USD"},
            "TimeUnit": "MONTHLY",
            "BudgetType": "COST",
        },
    )
    ctx.on_cleanup(lambda: budgets.delete_budget(AccountId=account_id, BudgetName=budget_name))

    ghost_role_name = ctx.unique_name("sim2real-budgets-ghost-role-")
    ghost_role_arn = f"arn:aws:iam::{account_id}:role/{ghost_role_name}"

    error = _error(
        lambda: budgets.create_budget_action(
            AccountId=account_id,
            BudgetName=budget_name,
            NotificationType="ACTUAL",
            ActionType="APPLY_IAM_POLICY",
            ActionThreshold={"ActionThresholdValue": 80.0, "ActionThresholdType": "PERCENTAGE"},
            Definition={
                "IamActionDefinition": {
                    "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
                    "Roles": [ghost_role_name],
                }
            },
            ExecutionRoleArn=ghost_role_arn,
            ApprovalModel="MANUAL",
            Subscribers=[{"SubscriptionType": "EMAIL", "Address": "sim2real-budgets-badrole@example.com"}],
        )
    )
    assert error["Code"] == "AccessDeniedException", f"expected AccessDeniedException, got {error['Code']!r}"
    expected_message = (
        f"Budgets permission required to assume [ExecutionRole: {ghost_role_arn}]. Please follow the "
        "instruction to grant assumeRole access to [Service Principal: budgets.amazonaws.com]."
    )
    assert error.get("Message") == expected_message, f"expected {expected_message!r}, got {error.get('Message')!r}"
    actions = budgets.describe_budget_actions_for_budget(AccountId=account_id, BudgetName=budget_name)[
        "Actions"
    ]
    assert actions == [], f"expected no budget actions after the rejected create, got {actions!r}"

    # Positive control: the same request with a real, assumable execution role succeeds.
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
        Subscribers=[{"SubscriptionType": "EMAIL", "Address": "sim2real-budgets-badrole-control@example.com"}],
    )
    action_id = resp["ActionId"]
    ctx.on_cleanup(
        lambda: budgets.delete_budget_action(AccountId=account_id, BudgetName=budget_name, ActionId=action_id)
    )
    described = budgets.describe_budget_action(
        AccountId=account_id, BudgetName=budget_name, ActionId=action_id
    )["Action"]
    assert described["Status"] == "STANDBY", f"expected STANDBY status for a freshly created action, got {described['Status']!r}"


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


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
    import time

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
    """Call fn(); return its ClientError's Error dict. An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected AccessDeniedException, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
