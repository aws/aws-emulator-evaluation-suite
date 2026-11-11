"""stack-instances-deployment-ordering."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-instances-deployment-ordering"
GROUP = 'stack_sets'
SERVICES = ['cloudformation']


def _client_error(fn):
    """Call fn(); return (Error.Code, Error.Message) if a ClientError is raised. Raises if fn unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")

def _wait_stack_set_operation(cf, ss_name, op_id, targets, timeout_s=300, interval_s=3):
    """Poll DescribeStackSetOperation until Status is in targets; return the operation dict."""
    target = {targets} if isinstance(targets, str) else set(targets)
    deadline = time.monotonic() + timeout_s
    op = None
    while time.monotonic() < deadline:
        op = cf.describe_stack_set_operation(StackSetName=ss_name, OperationId=op_id)["StackSetOperation"]
        if op.get("Status") in target:
            return op
        time.sleep(interval_s)
    raise AssertionError(f"stack set operation {op_id} did not reach {target} (last={op.get('Status') if op else None!r})")

def _parameterized_topic_template(logical_id="Topic", default="v1"):
    return json.dumps({
        "Parameters": {"TagValue": {"Type": "String", "Default": default}},
        "Resources": {logical_id: {"Type": "AWS::SNS::Topic",
            "Properties": {"Tags": [{"Key": "probe", "Value": {"Ref": "TagValue"}}]}}},
        "Outputs": {"TopicArn": {"Value": {"Ref": logical_id}}},
    })

def _retry_on_malformed_principal(fn, attempts=20, delay_s=15.0):
    """IAM has a brief eventual-consistency window right after CreateRole during
    which the new role's ARN isn't yet valid as a Principal in another role's
    trust policy (MalformedPolicyDocument). Retry past that transient window
    instead of a fixed sleep."""
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "MalformedPolicyDocument":
                raise
            last_exc = exc
            time.sleep(delay_s)
    raise last_exc

def _setup_self_managed_roles(ctx):
    """Create a throwaway admin/exec self-managed StackSet role pair; return (admin_arn, exec_name)."""
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    admin_name = ctx.unique_name("sim2real-behav-cfn-admin-")
    exec_name = ctx.unique_name("sim2real-behav-cfn-exec-")
    admin_trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Principal": {"Service": "cloudformation.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    admin = iam.create_role(RoleName=admin_name, AssumeRolePolicyDocument=json.dumps(admin_trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=admin_name))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=admin_name, PolicyName="AssumeExecRole"))
    exec_trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{account_id}:role/{admin_name}"}, "Action": "sts:AssumeRole"}]}
    _retry_on_malformed_principal(
        lambda: iam.create_role(RoleName=exec_name, AssumeRolePolicyDocument=json.dumps(exec_trust))
    )
    admin_policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    iam.attach_role_policy(RoleName=exec_name, PolicyArn=admin_policy_arn)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=exec_name))
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=exec_name, PolicyArn=admin_policy_arn))
    assume_policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Action": "sts:AssumeRole", "Resource": f"arn:aws:iam::{account_id}:role/{exec_name}"}]}
    iam.put_role_policy(RoleName=admin_name, PolicyName="AssumeExecRole", PolicyDocument=json.dumps(assume_policy))
    _wait_inline_policy_visible(iam, admin_name, "AssumeExecRole")
    return admin["Role"]["Arn"], exec_name


def _wait_inline_policy_visible(iam, role_name, policy_name, timeout_s=60, interval_s=3):
    """Poll GetRolePolicy until the just-written inline policy is readable; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)

def _teardown_stack_set(cf, name):
    """Delete any instances (wait for the op), then delete the stack set."""
    try:
        summaries = cf.list_stack_instances(StackSetName=name).get("Summaries", [])
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "StackSetNotFoundException":
            return
        raise
    if summaries:
        accounts = sorted({s["Account"] for s in summaries})
        regions = sorted({s["Region"] for s in summaries})
        try:
            # Delete regions in parallel (not the default MaxConcurrentCount=1) so
            # this teardown -- which must finish before the roles it depends on can
            # be deleted -- fits inside the shared cleanup budget.
            op = cf.delete_stack_instances(
                StackSetName=name, Accounts=accounts, Regions=regions, RetainStacks=False,
                OperationPreferences={"RegionConcurrencyType": "PARALLEL", "MaxConcurrentCount": max(len(regions), 1)},
            )
            _wait_stack_set_operation(cf, name, op["OperationId"], {"SUCCEEDED", "FAILED", "STOPPED"})
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "OperationNotFoundException",
                "StackSetNotFoundException",
            ):
                raise
    try:
        cf.delete_stack_set(StackSetName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StackSetNotFoundException":
            raise


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateStackInstances echoes the caller's OperationPreferences verbatim on the operation and
    deploys every instance to CURRENT, while an out-of-range preference value is rejected rather
    than silently clamped."""
    cf = ctx.client("cloudformation")
    admin_arn, exec_name = _setup_self_managed_roles(ctx)
    name = ctx.unique_name("sim2real-behav-ss-deploy-")
    cf.create_stack_set(
        StackSetName=name,
        TemplateBody=_parameterized_topic_template(),
        PermissionModel="SELF_MANAGED",
        AdministrationRoleARN=admin_arn,
        ExecutionRoleName=exec_name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _teardown_stack_set(cf, name))
    account = ctx.client("sts").get_caller_identity()["Account"]
    region1 = ctx.region
    # us-east-1/us-west-2 are Standard (default-enabled) partition regions, never
    # opt-in, so a second region distinct from ctx.region is guaranteed reachable
    # in any account -- needed to exercise cross-region RegionOrder/concurrency.
    region2 = "us-east-1" if ctx.region != "us-east-1" else "us-west-2"

    prefs = {
        "RegionConcurrencyType": "SEQUENTIAL",
        "RegionOrder": [region1, region2],
        "MaxConcurrentCount": 1,
        "FailureToleranceCount": 0,
    }
    # StackSets assumes the new role pair asynchronously, so an IAM-propagation miss
    # surfaces as a FAILED operation; retry the whole create-then-poll within a bound.
    deadline = time.monotonic() + 180
    while True:
        op = cf.create_stack_instances(
            StackSetName=name,
            Accounts=[account],
            Regions=[region1, region2],
            OperationPreferences=prefs,
        )
        op_id = op["OperationId"]
        result = _wait_stack_set_operation(cf, name, op_id, {"SUCCEEDED", "FAILED", "STOPPED"})
        if result["Status"] == "SUCCEEDED" or time.monotonic() >= deadline:
            break
        time.sleep(2)
    assert result["Status"] == "SUCCEEDED", result

    # The configured deployment ordering/concurrency settings must be
    # echoed back on the operation, not silently dropped.
    described = cf.describe_stack_set_operation(StackSetName=name, OperationId=op_id)["StackSetOperation"]
    echoed = described.get("OperationPreferences", {})
    assert echoed.get("RegionConcurrencyType") == "SEQUENTIAL", echoed
    assert echoed.get("RegionOrder") == [region1, region2], echoed

    summaries = cf.list_stack_instances(StackSetName=name)["Summaries"]
    regions_seen = {s["Region"]: s["Status"] for s in summaries}
    assert regions_seen.get(region1) == "CURRENT", regions_seen
    assert regions_seen.get(region2) == "CURRENT", regions_seen

    for region in (region1, region2):
        instance = cf.describe_stack_instance(
            StackSetName=name, StackInstanceAccount=account, StackInstanceRegion=region
        )["StackInstance"]
        assert instance["Status"] == "CURRENT", instance

    results = cf.list_stack_set_operation_results(StackSetName=name, OperationId=op_id)["Summaries"]
    result_regions = {r["Region"] for r in results}
    assert {region1, region2}.issubset(result_regions), results

    # Overly-permissive boundary: MaxConcurrentPercentage must be 1-100;
    # a value outside that range must be rejected, not clamped/ignored.
    bad_name = ctx.unique_name("sim2real-behav-ss-deploy-bad-")
    cf.create_stack_set(
        StackSetName=bad_name,
        TemplateBody=_parameterized_topic_template(),
        PermissionModel="SELF_MANAGED",
        AdministrationRoleARN=admin_arn,
        ExecutionRoleName=exec_name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _teardown_stack_set(cf, bad_name))
    code, msg = _client_error(
        lambda: cf.create_stack_instances(
            StackSetName=bad_name,
            Accounts=[account],
            Regions=[region1],
            OperationPreferences={"MaxConcurrentPercentage": 150},
        )
    )
    assert code == "ValidationError", f"expected ValidationError for an out-of-range MaxConcurrentPercentage, got {code!r}"
    assert msg == (
        "1 validation error detected: Value '150' at 'operationPreferences.maxConcurrentPercentage' "
        "failed to satisfy constraint: Member must have value less than or equal to 100"
    ), msg

    # The rejected call must not have started an operation or created an instance.
    bad_summaries = cf.list_stack_instances(StackSetName=bad_name).get("Summaries", [])
    assert bad_summaries == [], f"rejected create_stack_instances must not create any instances, got {bad_summaries}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
