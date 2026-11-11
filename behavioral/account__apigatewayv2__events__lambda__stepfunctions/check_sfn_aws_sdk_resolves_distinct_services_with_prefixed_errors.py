"""sfn-aws-sdk-resolves-distinct-services-with-prefixed-errors."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-aws-sdk-resolves-distinct-services-with-prefixed-errors"
GROUP = "aws_sdk_integrations"
SERVICES = ["account", "apigatewayv2", "events", "lambda", "stepfunctions"]


@tags("axis:rejection", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data", "cap:c3")
def run(ctx) -> None:
    """A least-privilege role lets a Task's aws-sdk integration dispatch to four distinct
    services (account, apigatewayv2, eventbridge, lambda) in one execution; omitting just one
    of the four grants fails only that service's call, named '<ServicePrefix>.<Exception>'.
    """
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    full_role_arn = _create_role(ctx, [
        {"Effect": "Allow", "Action": "account:ListRegions", "Resource": "*"},
        {"Effect": "Allow", "Action": "apigateway:GET", "Resource": "*"},
        {"Effect": "Allow", "Action": "events:ListApiDestinations", "Resource": "*"},
        {"Effect": "Allow", "Action": "lambda:ListCodeSigningConfigs", "Resource": "*"},
    ])
    definition = {
        "Comment": "one aws-sdk task per service, run in parallel under one least-privilege role",
        "StartAt": "Fan",
        "States": {
            "Fan": {
                "Type": "Parallel",
                "Branches": [
                    {"StartAt": "Account", "States": {"Account": {
                        "Type": "Task", "Resource": "arn:aws:states:::aws-sdk:account:listRegions",
                        "Parameters": {}, "End": True,
                    }}},
                    {"StartAt": "ApiGatewayV2", "States": {"ApiGatewayV2": {
                        "Type": "Task", "Resource": "arn:aws:states:::aws-sdk:apigatewayv2:getApis",
                        "Parameters": {}, "End": True,
                    }}},
                    {"StartAt": "EventBridge", "States": {"EventBridge": {
                        "Type": "Task",
                        "Resource": "arn:aws:states:::aws-sdk:eventbridge:listApiDestinations",
                        "Parameters": {}, "End": True,
                    }}},
                    {"StartAt": "Lambda", "States": {"Lambda": {
                        "Type": "Task",
                        "Resource": "arn:aws:states:::aws-sdk:lambda:listCodeSigningConfigs",
                        "Parameters": {}, "End": True,
                    }}},
                ],
                "End": True,
            }
        },
    }
    full_sm_arn = _create_state_machine(ctx, definition, full_role_arn)

    # The role's inline grants can still be propagating right after CreateStateMachine, so a
    # branch denied access re-runs a fresh execution; the assertions below read the final run.
    good = _run_to_terminal(ctx, full_sm_arn, {}, skip_markers=_GRANT_PROPAGATION_MARKERS)
    assert good["status"] == "SUCCEEDED", (
        f"the 4-branch execution under the least-privilege role ended {good['status']!r}: "
        f"{good.get('error')!r} {good.get('cause')!r}"
    )
    branch_out = json.loads(good["output"])
    assert len(branch_out) == 4, f"expected 4 branch outputs, got {len(branch_out)}: {branch_out!r}"
    account_out, apigw_out, events_out, lambda_out = branch_out

    assert isinstance(account_out.get("Regions"), list) and account_out["Regions"], (
        f"account:listRegions returned no Regions: {account_out!r}"
    )
    assert all("RegionName" in r for r in account_out["Regions"]), (
        f"a Regions entry had no RegionName: {account_out['Regions']!r}"
    )
    assert "Items" in apigw_out, f"apigatewayv2:getApis response had no Items: {apigw_out!r}"
    assert "ApiDestinations" in events_out, (
        f"eventbridge:listApiDestinations response had no ApiDestinations: {events_out!r}"
    )
    assert "CodeSigningConfigs" in lambda_out, (
        f"lambda:listCodeSigningConfigs response had no CodeSigningConfigs: {lambda_out!r}"
    )

    # Break exactly one of the four grants: a role with the other three but not account:ListRegions.
    restricted_role_arn = _create_role(ctx, [
        {"Effect": "Allow", "Action": "apigateway:GET", "Resource": "*"},
        {"Effect": "Allow", "Action": "events:ListApiDestinations", "Resource": "*"},
        {"Effect": "Allow", "Action": "lambda:ListCodeSigningConfigs", "Resource": "*"},
    ])
    denied_definition = {
        "StartAt": "Account",
        "States": {"Account": {
            "Type": "Task", "Resource": "arn:aws:states:::aws-sdk:account:listRegions",
            "Parameters": {}, "End": True,
        }},
    }
    restricted_sm_arn = _create_state_machine(ctx, denied_definition, restricted_role_arn)

    denied = _run_to_terminal(ctx, restricted_sm_arn, {})
    assert denied["status"] == "FAILED", (
        f"account:listRegions without the account:ListRegions grant ended "
        f"{denied['status']!r}, expected FAILED: {denied.get('cause')!r}"
    )
    assert denied.get("error") == "Account.AccessDeniedException", (
        f"expected the service error to be named 'Account.AccessDeniedException', "
        f"got {denied.get('error')!r} ({denied.get('cause')!r})"
    )
    # The cause carries a Step-Functions-chosen session name and a per-call request id, neither
    # a value this check can predict, so only the service-prefixed error name is asserted exact.
    assert f":{account_id}:" in (denied.get("cause") or ""), (
        f"the denial cause did not name this execution's own account: {denied.get('cause')!r}"
    )


# ===== helpers =====
_TERMINAL = ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED")
_ROLE_PROPAGATION_MARKERS = (
    "not authorized to assume",
    "cannot be assumed",
    "is not authorized to perform: sts:AssumeRole",
)
# A just-created role's inline grants can still be propagating when the full-grant machine
# first runs; only that run retries on a service denial, never the restricted run whose
# account denial is the asserted outcome.
_GRANT_PROPAGATION_MARKERS = ("AccessDenied", "not authorized")


def _create_role(ctx, statements):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnsdk-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    })
    role_arn = ctx.client("iam").create_role(
        RoleName=role_name, AssumeRolePolicyDocument=trust,
        Description="sim2real-behav sfn aws-sdk least-privilege execution role",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]

    def _delete_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_delete_role)
    iam.put_role_policy(
        RoleName=role_name, PolicyName="inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    # IAM propagation exposes no condition to poll; the bounded retries in _create_state_machine
    # and _run_to_terminal absorb it.
    return role_arn


def _create_state_machine(ctx, definition, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sdksm-")
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type="STANDARD",
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateStateMachine never stopped denying the role: {last!r}")


def _best_effort_stop(ctx, exec_arn):
    try:
        ctx.client("stepfunctions").stop_execution(
            executionArn=exec_arn, error="SimCleanup", cause="sim2real cleanup")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _poll(probe, predicate, *, timeout_s, what, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{what}: not reached within {timeout_s}s; last={last!r}")


def _run_to_terminal(ctx, sm_arn, payload, *, timeout_s=120, attempts=8, skip_markers=None):
    """Start an execution and poll to terminal, retrying a fresh one only while it fails on the
    role-trust race or one of ``skip_markers``; raise once ``attempts`` are spent."""
    sfn = ctx.client("stepfunctions")
    retry_markers = _ROLE_PROPAGATION_MARKERS + tuple(skip_markers or ())
    desc = None
    for _ in range(attempts):
        exec_arn = sfn.start_execution(
            stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-"),
            input=json.dumps(payload),
        )["executionArn"]
        ctx.on_cleanup(lambda a=exec_arn: _best_effort_stop(ctx, a))
        desc = _poll(lambda a=exec_arn: sfn.describe_execution(executionArn=a),
                     lambda d: d["status"] in _TERMINAL, timeout_s=timeout_s,
                     what=f"execution {exec_arn} terminal")
        blob = (desc.get("error") or "") + (desc.get("cause") or "")
        if desc["status"] != "FAILED" or not any(m in blob for m in retry_markers):
            return desc
        time.sleep(5)
    raise AssertionError(
        f"every one of {attempts} executions of {sm_arn} failed on a propagation marker; "
        f"last error {desc.get('error')!r}: {desc.get('cause')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
