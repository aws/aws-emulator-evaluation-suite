"""deploy-secretsmanager-rotationschedule-enabled-then-disabled-by-stack-update."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-secretsmanager-rotationschedule-enabled-then-disabled-by-stack-update"
GROUP = "deploy"
SERVICES = ["cloudformation", "iam", "lambda", "secretsmanager"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----

_SECRET_GONE = ("ResourceNotFoundException", "Secrets Manager can't find the specified secret.")

# Ten days out, so no scheduled rotation can fire during the run.
_SCHEDULE_EXPRESSION = "rate(10 days)"
_ROLE_POLICY_NAME = "sim2real-rotate-policy"
_LOG_ACTIONS = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
# GenerateSecretString with no options yields a 32-character password.
_DEFAULT_PASSWORD_LENGTH = 32

_LAMBDA_SRC = """def lambda_handler(event, context):
    return
"""


def _template(secret_name: str, function_name: str, with_rotation: bool) -> str:
    resources = {
        "RotationRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }],
                },
                "Policies": [{
                    "PolicyName": _ROLE_POLICY_NAME,
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Action": _LOG_ACTIONS,
                            "Resource": "*",
                        }],
                    },
                }],
            },
        },
        "RotationFunction": {
            "Type": "AWS::Lambda::Function",
            "Properties": {
                "FunctionName": function_name,
                "Runtime": "python3.12",
                "Handler": "index.lambda_handler",
                "Role": {"Fn::GetAtt": ["RotationRole", "Arn"]},
                "Timeout": 30,
                "Code": {"ZipFile": _LAMBDA_SRC},
            },
        },
        "InvokePermission": {
            "Type": "AWS::Lambda::Permission",
            "Properties": {
                "FunctionName": {"Ref": "RotationFunction"},
                "Action": "lambda:InvokeFunction",
                "Principal": "secretsmanager.amazonaws.com",
            },
        },
        "Secret": {
            "Type": "AWS::SecretsManager::Secret",
            "Properties": {"Name": secret_name, "GenerateSecretString": {}},
        },
    }
    if with_rotation:
        resources["RotationSchedule"] = {
            "Type": "AWS::SecretsManager::RotationSchedule",
            "DependsOn": "InvokePermission",
            "Properties": {
                "SecretId": {"Ref": "Secret"},
                "RotationLambdaARN": {"Fn::GetAtt": ["RotationFunction", "Arn"]},
                "RotationRules": {"ScheduleExpression": _SCHEDULE_EXPRESSION},
                "RotateImmediatelyOnUpdate": False,
            },
        }
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": resources,
        "Outputs": {
            "SecretArn": {"Value": {"Ref": "Secret"}},
            "FunctionArn": {"Value": {"Fn::GetAtt": ["RotationFunction", "Arn"]}},
        },
    }


def _listed_arns(sm, name: str) -> list[str]:
    """ARNs of the secrets ListSecrets returns under exactly ``name``, every page read."""
    arns: list[str] = []
    pages = sm.get_paginator("list_secrets").paginate(Filters=[{"Key": "name", "Values": [name]}])
    for page in pages:
        arns.extend(s["ARN"] for s in page["SecretList"] if s["Name"] == name)
    return arns


def _poll_rotation_disabled(sm, secret_arn: str, *, timeout_s: float = 60.0) -> dict:
    """DescribeSecret until RotationEnabled reads false; return that read."""
    deadline = time.monotonic() + timeout_s
    while True:
        described = sm.describe_secret(SecretId=secret_arn)
        if described.get("RotationEnabled", False) is False or time.monotonic() > deadline:
            return described
        time.sleep(2.0)


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0,
                     budget_s: float = 45.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent.

    A rotation test-invoke's buffered log stream can flush after delete and recreate the group.
    """
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group {name!r} still present after {budget_s}s of deletes; "
                    f"{absent} clean reads"
                )
            time.sleep(interval_s)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy",
      "concern:representation", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A CFN RotationSchedule enables rotation at SecretsManager with the template's own
    RotationRules and Lambda ARN. A stack update dropping it disables rotation there too, and
    the secret is only actually gone once the whole stack is deleted.
    """
    cfn = ctx.client("cloudformation")
    sm = ctx.client("secretsmanager")
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    secret_name = ctx.unique_name("sim2real-behav-cfn-smrs-")
    stack_name = ctx.unique_name("sim2real-behav-cfn-smrs-")
    function_name = ctx.unique_name("sim2real-behav-cfn-smrs-")

    # Registered before the function is created, so LIFO runs it after the stack's delete.
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{function_name}"))

    stack_id = create_stack(
        ctx, cfn, stack_name,
        json.dumps(_template(secret_name, function_name, with_rotation=True)),
        Capabilities=["CAPABILITY_IAM"],
    )
    created = wait_stack(cfn, stack_id)
    assert created == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE, got {created!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )

    outputs = stack_outputs(cfn, stack_id)
    secret_arn = outputs["SecretArn"]
    function_arn = outputs["FunctionArn"]

    # ---- the secret: Ref is the ARN ListSecrets returns for its name, and its generated value
    # is readable; its identity is captured to prove the update leaves it in place ----
    listed = _listed_arns(sm, secret_name)
    assert listed == [secret_arn], (
        f"expected ListSecrets to return Ref {secret_arn!r} for {secret_name!r}, got {listed!r}"
    )
    value = sm.get_secret_value(SecretId=secret_arn)
    assert len(value["SecretString"]) == _DEFAULT_PASSWORD_LENGTH, (
        f"expected a {_DEFAULT_PASSWORD_LENGTH}-character generated SecretString, got "
        f"{len(value['SecretString'])} characters"
    )
    before_value = (value["ARN"], value["Name"], value["VersionId"], value["SecretString"])

    # ---- the function, its role and its permission are real at Lambda and IAM ----
    fn_config = lam.get_function_configuration(FunctionName=function_name)
    got_fn = (fn_config["FunctionArn"], fn_config["Runtime"], fn_config["Handler"],
              fn_config["Timeout"])
    want_fn = (function_arn, "python3.12", "index.lambda_handler", 30)
    assert got_fn == want_fn, f"expected the function (arn, runtime, handler, timeout) {want_fn!r}, got {got_fn!r}"
    role_name = fn_config["Role"].rsplit("/", 1)[1]
    role_policy = iam.get_role_policy(RoleName=role_name, PolicyName=_ROLE_POLICY_NAME)
    statements = [(st["Effect"], st["Action"], st["Resource"])
                  for st in role_policy["PolicyDocument"]["Statement"]]
    assert statements == [("Allow", _LOG_ACTIONS, "*")], (
        f"expected the role's inline policy to allow {_LOG_ACTIONS!r}, IAM reports {statements!r}"
    )
    permission = json.loads(lam.get_policy(FunctionName=function_name)["Policy"])
    grants = [(st["Effect"], st["Principal"], st["Action"], st["Resource"])
              for st in permission["Statement"]]
    want_grant = [("Allow", {"Service": "secretsmanager.amazonaws.com"}, "lambda:InvokeFunction",
                   function_arn)]
    assert grants == want_grant, f"expected the function policy {want_grant!r}, got {grants!r}"

    # ---- RotationSchedule: enabled at SecretsManager, GetAtt Arn equals the service's own value,
    # and the declared RotationRules read back exactly. ----
    described = sm.describe_secret(SecretId=secret_arn)
    assert (described["ARN"], described["Name"]) == (secret_arn, secret_name), (
        f"expected DescribeSecret to name {(secret_arn, secret_name)!r}, got "
        f"{(described['ARN'], described['Name'])!r}"
    )
    created_date = described["CreatedDate"]
    assert described["RotationEnabled"] is True, (
        f"expected RotationEnabled True after RotationSchedule create, got "
        f"{described.get('RotationEnabled')!r}"
    )
    assert described["RotationLambdaARN"] == function_arn, (
        f"expected RotationLambdaARN to equal the GetAtt FunctionArn output {function_arn!r}, "
        f"got {described.get('RotationLambdaARN')!r}"
    )
    # SecretsManager derives AutomaticallyAfterDays from a day-granularity rate() expression and
    # echoes both back.
    expected_rules = {"ScheduleExpression": _SCHEDULE_EXPRESSION, "AutomaticallyAfterDays": 10}
    assert described["RotationRules"] == expected_rules, (
        f"expected RotationRules {expected_rules!r}, got {described.get('RotationRules')!r}"
    )

    # ---- update: drop the RotationSchedule resource, keeping the secret, role, function ----
    cfn.update_stack(
        StackName=stack_id,
        TemplateBody=json.dumps(_template(secret_name, function_name, with_rotation=False)),
        Capabilities=["CAPABILITY_IAM"],
    )
    updated = wait_stack(cfn, stack_id)
    assert updated == "UPDATE_COMPLETE", f"expected UPDATE_COMPLETE, got {updated!r}"

    resources = {
        r["LogicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    }
    assert "RotationSchedule" not in resources, (
        f"RotationSchedule logical resource still present after the update: {resources!r}"
    )

    # The removal is real at SecretsManager, not merely reported by CFN: DescribeSecret still
    # answers for this still-valid SecretId, but reports rotation disabled.
    after = _poll_rotation_disabled(sm, secret_arn)
    assert after.get("RotationEnabled", False) is False, (
        f"secret {secret_arn!r} still reports RotationEnabled after the RotationSchedule resource "
        f"was removed by the stack update: {after.get('RotationEnabled')!r}"
    )

    # The update leaves the same secret in place: creation date, version and value unchanged.
    assert after["CreatedDate"] == created_date, (
        f"the secret's CreatedDate changed across the update: {created_date!r} -> "
        f"{after['CreatedDate']!r}"
    )
    after_value = sm.get_secret_value(SecretId=secret_arn)
    after_tuple = (after_value["ARN"], after_value["Name"], after_value["VersionId"],
                   after_value["SecretString"])
    assert after_tuple == before_value, (
        f"the secret's (ARN, Name, VersionId) changed across the update: {before_value[:3]!r} -> "
        f"{after_tuple[:3]!r}, SecretString unchanged: {after_tuple[3] == before_value[3]!r}"
    )

    # ---- full delete: the secret is only actually gone once the stack itself is torn down ----
    delete_stack(cfn, stack_id)
    expect_error(lambda: sm.describe_secret(SecretId=secret_arn), *_SECRET_GONE)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
