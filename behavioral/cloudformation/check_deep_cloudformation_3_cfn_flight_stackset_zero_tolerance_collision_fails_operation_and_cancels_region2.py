"""deep-cloudformation-3-cfn-flight-stackset-zero-tolerance-collision-fails-operation-and-cancels-region2."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-cloudformation-3-cfn-flight-stackset-zero-tolerance-collision-fails-operation-and-cancels-region2"
GROUP = "stack_sets"
SERVICES = ["cloudformation"]


@tags("cap:c3", "concern:negative-classes", "plane:control", "axis:rejection")
def run(ctx) -> None:
    """A SEQUENTIAL stack-set fan-out with FailureToleranceCount=0 stops at the first failed
    region: region 1 fails on a planted name collision, the operation ends FAILED, region 2 is
    never attempted."""
    cf = ctx.client("cloudformation")
    account = ctx.client("sts").get_caller_identity()["Account"]
    region1 = ctx.region
    # us-east-1 / us-west-2 are default-enabled commercial regions (never opt-in), so a region
    # distinct from ctx.region is always reachable; a stack-set fan-out needs a second region.
    region2 = "us-east-1" if region1 != "us-east-1" else "us-west-2"

    admin_arn, exec_name = _setup_self_managed_roles(ctx)

    # Plant the collision in region 1 ONLY, before the operation starts: region 2 has no such
    # parameter, so the identical template would succeed there if it were attempted.
    param_name = ctx.unique_name("sim2real-behav-cfnflight-p0-")
    ssm1 = ctx.client("ssm", region=region1)
    ssm1.put_parameter(Name=param_name, Value="planted-by-check", Type="String",
                       Tags=[{"Key": "sim2real-check", "Value": "cfn-flight"}])
    ctx.on_cleanup(lambda: ssm1.delete_parameter(Name=param_name))
    ssm2 = ctx.client("ssm", region=region2)
    assert _get_parameter_error(ssm2, param_name) == ("ParameterNotFound", ""), (
        f"parameter {param_name!r} unexpectedly exists in {region2}; the collision must be region-1-only"
    )

    # Each stack set gets ONE teardown net for its multi-region estate: issue the deletes, then wait.
    name, op_id, op = _deploy_once_roles_usable(
        ctx,
        cf,
        "sim2real-behav-cfnflight-ss0-",
        create_set=dict(
            TemplateBody=_ssm_param_template(),
            Parameters=[{"ParameterKey": "ParamName", "ParameterValue": param_name}],
            PermissionModel="SELF_MANAGED",
            AdministrationRoleARN=admin_arn,
            ExecutionRoleName=exec_name,
            Tags=[{"Key": "sim2real-check", "Value": "cfn-flight"}],
        ),
        create_instances=dict(
            Accounts=[account],
            Regions=[region1, region2],
            OperationPreferences={
                "RegionConcurrencyType": "SEQUENTIAL",
                "RegionOrder": [region1, region2],
                "MaxConcurrentCount": 1,
                "FailureToleranceCount": 0,
            },
        ),
    )

    # (a) the operation as a whole failed — tolerance 0 was exceeded by the region-1 failure.
    assert op["Status"] == "FAILED", (
        f"operation {op_id} ended {op['Status']!r}, expected 'FAILED' (region-1 collision with tolerance 0); op={op!r}"
    )

    instances = _instances(cf, name)
    # (b) region 1 was attempted and failed on the planted collision.
    r1 = instances.get(region1)
    assert r1 is not None, f"no stack-instance record for {region1}; instances={instances!r}"
    r1_detail = r1.get("StackInstanceStatus", {}).get("DetailedStatus")
    assert r1_detail == "FAILED", (
        f"region-1 instance DetailedStatus is {r1_detail!r}, expected 'FAILED'; instance={r1!r}"
    )
    # The instance's StatusReason is a generic "Validation failed with 1 error(s)" pointer; the
    # region-1 stack's own DescribeEvents names the actual cause, which must be OUR collision.
    r1_stack = r1.get("StackId")
    assert r1_stack, f"region-1 instance has no StackId, so it was never attempted; instance={r1!r}"
    conflicts = _validation_errors(ctx.client("cloudformation", region=region1), r1_stack)
    assert conflicts == [(
        "NAME_CONFLICT_VALIDATION",
        f"Resource of type 'AWS::SSM::Parameter' with identifier '{param_name}' already exists.",
    )], f"region-1 stack validation errors were {conflicts!r}, expected exactly the planted name conflict"

    # (c) region 2 was NEVER attempted. Evidence used: its instance record exists with
    # DetailedStatus CANCELLED and it was never given a stack (no StackId).
    r2 = instances.get(region2)
    assert r2 is not None, f"no stack-instance record for {region2}; instances={instances!r}"
    r2_detail = r2.get("StackInstanceStatus", {}).get("DetailedStatus")
    assert r2_detail == "CANCELLED", (
        f"region-2 instance DetailedStatus is {r2_detail!r}, expected 'CANCELLED' (never attempted); instance={r2!r}"
    )
    assert not r2.get("StackId"), (
        f"region-2 instance carries a StackId {r2.get('StackId')!r}, i.e. a stack was created there; instance={r2!r}"
    )
    # Effect absent: the template's parameter was never written in region 2.
    assert _get_parameter_error(ssm2, param_name) == ("ParameterNotFound", ""), (
        f"parameter {param_name!r} exists in {region2}: region 2 was deployed despite tolerance 0"
    )

    # Per-region operation results agree with the instance view.
    results = {r["Region"]: r["Status"] for r in _op_results(cf, name, op_id)}
    assert results.get(region1) == "FAILED", f"region-1 operation result is {results.get(region1)!r}; results={results!r}"
    assert results.get(region2) == "CANCELLED", f"region-2 operation result is {results.get(region2)!r}; results={results!r}"



def _ssm_param_template() -> str:
    return json.dumps({
        "Parameters": {"ParamName": {"Type": "String"}},
        "Resources": {"Param": {"Type": "AWS::SSM::Parameter",
                                "Properties": {"Name": {"Ref": "ParamName"}, "Type": "String",
                                               "Value": "written-by-stack-set"}}},
    })


def _get_parameter_error(ssm, name: str):
    """GetParameter's (error code, message). Raises if the parameter unexpectedly exists."""
    try:
        found = ssm.get_parameter(Name=name)["Parameter"]
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"parameter {name!r} exists with value {found.get('Value')!r}")


def _validation_errors(cf, stack_id: str) -> list:
    """(ValidationName, ValidationStatusReason) of every VALIDATION_ERROR event on the stack."""
    out, token = [], None
    while True:
        kw = {"StackName": stack_id, "Filters": {"FailedEvents": True}}
        if token:
            kw["NextToken"] = token
        page = cf.describe_events(**kw)
        out.extend((e.get("ValidationName"), e.get("ValidationStatusReason"))
                   for e in page.get("OperationEvents", []) if e.get("EventType") == "VALIDATION_ERROR")
        token = page.get("NextToken")
        if not token:
            return out


def _instances(cf, name: str) -> dict:
    out = {}
    for page in cf.get_paginator("list_stack_instances").paginate(StackSetName=name):
        for s in page.get("Summaries", []):
            out[s["Region"]] = s
    return out


def _op_results(cf, name: str, op_id: str) -> list:
    out = []
    for page in cf.get_paginator("list_stack_set_operation_results").paginate(StackSetName=name, OperationId=op_id):
        out.extend(page.get("Summaries", []))
    return out


def _wait_stack_set_operation(cf, ss_name, op_id, targets, timeout_s=300, interval_s=4):
    deadline = time.monotonic() + timeout_s
    op = None
    while time.monotonic() < deadline:
        op = cf.describe_stack_set_operation(StackSetName=ss_name, OperationId=op_id)["StackSetOperation"]
        if op.get("Status") in targets:
            return op
        time.sleep(interval_s)
    raise AssertionError(f"stack set operation {op_id} did not reach {targets} (last={op.get('Status') if op else None!r})")


def _deadline(ctx, seconds):
    left = ctx.time_left()
    return time.monotonic() + (seconds if left is None else min(seconds, left))


# Operation results naming role assumption: the just-created role pair has not propagated yet.
_ROLE_NOT_READY = ("assume", "trust relationship")


def _deploy_once_roles_usable(ctx, cf, prefix, *, create_set, create_instances, timeout_s=180.0):
    """Create a stack set and run its instance operation; returns (name, op_id, op). An operation
    refused on role assumption is rerun on a fresh stack set until a deadline."""
    deadline = _deadline(ctx, timeout_s)
    while True:
        name = ctx.unique_name(prefix)
        cf.create_stack_set(StackSetName=name, **create_set)
        ctx.on_cleanup(lambda name=name: _teardown_stack_set(cf, name))
        op_id = cf.create_stack_instances(StackSetName=name, **create_instances)["OperationId"]
        op = _wait_stack_set_operation(cf, name, op_id, {"SUCCEEDED", "FAILED", "STOPPED"}, timeout_s=600)
        reasons = [op.get("StatusReason") or ""]
        reasons += [r.get("StatusReason") or "" for r in _op_results(cf, name, op_id)]
        role_refused = any(m in r.lower() for r in reasons for m in _ROLE_NOT_READY)
        if not role_refused or time.monotonic() >= deadline:
            return name, op_id, op
        time.sleep(2)


def _retry_on_malformed_principal(ctx, fn, timeout_s=300.0):
    """IAM's eventual consistency: a just-created role ARN is briefly not a valid Principal."""
    deadline = _deadline(ctx, timeout_s)
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "MalformedPolicyDocument" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _setup_self_managed_roles(ctx):
    """A throwaway self-managed admin/exec role pair; returns (admin_arn, exec_name)."""
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    admin_name = ctx.unique_name("sim2real-behav-cfnflight-adm-")
    exec_name = ctx.unique_name("sim2real-behav-cfnflight-exe-")
    admin_trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Principal": {"Service": "cloudformation.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    admin = iam.create_role(RoleName=admin_name, AssumeRolePolicyDocument=json.dumps(admin_trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=admin_name))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=admin_name, PolicyName="AssumeExecRole"))
    exec_trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{account_id}:role/{admin_name}"}, "Action": "sts:AssumeRole"}]}
    _retry_on_malformed_principal(
        ctx,
        lambda: iam.create_role(RoleName=exec_name, AssumeRolePolicyDocument=json.dumps(exec_trust))
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=exec_name))
    admin_policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    iam.attach_role_policy(RoleName=exec_name, PolicyArn=admin_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=exec_name, PolicyArn=admin_policy_arn))
    assume_policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Action": "sts:AssumeRole", "Resource": f"arn:aws:iam::{account_id}:role/{exec_name}"}]}
    iam.put_role_policy(RoleName=admin_name, PolicyName="AssumeExecRole", PolicyDocument=json.dumps(assume_policy))
    # IAM propagation exposes no pollable condition: _deploy_once_roles_usable absorbs it at
    # the first operation that assumes the roles.
    return admin["Role"]["Arn"], exec_name


def _teardown_stack_set(cf, name):
    """Delete every instance in all regions at once (PARALLEL), wait, then delete the set."""
    try:
        summaries = [s for p in cf.get_paginator("list_stack_instances").paginate(StackSetName=name)
                     for s in p.get("Summaries", [])]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "StackSetNotFoundException":
            return
        raise
    if summaries:
        accounts = sorted({s["Account"] for s in summaries})
        regions = sorted({s["Region"] for s in summaries})
        try:
            op = cf.delete_stack_instances(
                StackSetName=name, Accounts=accounts, Regions=regions, RetainStacks=False,
                OperationPreferences={"RegionConcurrencyType": "PARALLEL",
                                      "MaxConcurrentCount": max(len(regions), 1),
                                      "FailureToleranceCount": max(len(regions) - 1, 0)},
            )
            _wait_stack_set_operation(cf, name, op["OperationId"], {"SUCCEEDED", "FAILED", "STOPPED"}, timeout_s=600)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("OperationNotFoundException", "StackSetNotFoundException"):
                raise
    try:
        cf.delete_stack_set(StackSetName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StackSetNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
