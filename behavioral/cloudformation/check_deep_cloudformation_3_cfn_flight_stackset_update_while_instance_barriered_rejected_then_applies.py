"""deep-cloudformation-3-cfn-flight-stackset-update-while-instance-barriered-rejected-then-applies."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-cloudformation-3-cfn-flight-stackset-update-while-instance-barriered-rejected-then-applies"
GROUP = "stack_sets"
SERVICES = ["cloudformation"]

_GATE = {"Type": "AWS::CloudFormation::WaitCondition",
         "CreationPolicy": {"ResourceSignal": {"Count": 1, "Timeout": "PT15M"}}}
_V1 = {"Resources": {"Anchor": {"Type": "AWS::CloudFormation::WaitConditionHandle"}, "Gate": _GATE}}
_V2 = {"Resources": {"Anchor": {"Type": "AWS::CloudFormation::WaitConditionHandle"}, "Gate": _GATE,
                     "Second": {"Type": "AWS::CloudFormation::WaitConditionHandle"}}}


@tags("cap:c3", "concern:negative-classes", "plane:control", "axis:rejection")
def run(ctx) -> None:
    """While CreateStackInstances is held by an unsignalled WaitCondition, UpdateStackSet is refused
    and not queued; after the barrier is signalled and op1 SUCCEEDS, the same update is applied."""
    cf = ctx.client("cloudformation")
    account = ctx.client("sts").get_caller_identity()["Account"]
    region = ctx.region
    admin_arn, exec_name = _setup_self_managed_roles(ctx)

    name = ctx.unique_name("sim2real-behav-cfnflight-ssu-")
    cf.create_stack_set(
        StackSetName=name, TemplateBody=json.dumps(_V1), PermissionModel="SELF_MANAGED",
        AdministrationRoleARN=admin_arn, ExecutionRoleName=exec_name,
        Tags=[{"Key": "sim2real-check", "Value": "cfn-flight"}],
    )
    ctx.on_cleanup(lambda: _teardown_stack_set(cf, name))

    op1_id, stack_id, discarded = _start_barriered_instance(cf, name, account, region)
    op1 = cf.describe_stack_set_operation(StackSetName=name, OperationId=op1_id)["StackSetOperation"]
    assert op1["Status"] == "RUNNING", f"op1 is {op1['Status']!r} while its instance is barriered, expected 'RUNNING'"

    # The competing request, sent twice byte-for-byte: refused now, accepted later. A
    # self-managed UpdateStackSet must restate the administration role or it is rejected
    # for a reason unrelated to concurrency.
    update_request = {"StackSetName": name, "TemplateBody": json.dumps(_V2),
                      "AdministrationRoleARN": admin_arn, "ExecutionRoleName": exec_name}
    # Negative: the competing stack-set operation is refused with the exact code.
    err = _client_error(lambda: cf.update_stack_set(**update_request))
    assert err.get("Code") == "OperationInProgressException", (
        f"UpdateStackSet during a running operation returned {err!r}, expected 'OperationInProgressException'"
    )
    stack_set_arn = cf.describe_stack_set(StackSetName=name)["StackSet"]["StackSetARN"]
    expected = f"Another Operation on StackSet {stack_set_arn} is in progress: {op1_id}"
    assert err.get("Message") == expected, f"expected {expected!r}, got {err.get('Message')!r}"
    # Effect absent: nothing queued, template unchanged, op1 still held at the barrier.
    ops = [o for o in _operations(cf, name) if o["OperationId"] not in discarded]
    assert [o["OperationId"] for o in ops] == [op1_id], f"operations after the refusal: {ops!r}; expected only op1"
    template = json.loads(cf.describe_stack_set(StackSetName=name)["StackSet"]["TemplateBody"])
    assert "Second" not in template.get("Resources", {}), "the refused UpdateStackSet changed the stack set's template"
    gate = cf.describe_stack_resource(StackName=stack_id, LogicalResourceId="Gate")["StackResourceDetail"]
    assert gate["ResourceStatus"] == "CREATE_IN_PROGRESS", (
        f"the refusal disturbed op1: its Gate is {gate['ResourceStatus']!r}"
    )

    # Release the barrier inside the instance stack; op1 must SUCCEED. The barrier is structural (a
    # CreationPolicy only SignalResource releases), so op1 cannot finish before the competing call.
    cf.signal_resource(StackName=stack_id, LogicalResourceId="Gate",
                       UniqueId=ctx.unique_name("sig-"), Status="SUCCESS")
    op1 = _wait_stack_set_operation(cf, name, op1_id, {"SUCCEEDED", "FAILED", "STOPPED"}, timeout_s=600)
    assert op1["Status"] == "SUCCEEDED", f"op1 ended {op1['Status']!r} after the signal, expected 'SUCCEEDED'; op={op1!r}"

    # Positive control: the identical UpdateStackSet is now accepted and applied downstream.
    op2_id = cf.update_stack_set(**update_request)["OperationId"]
    assert op2_id != op1_id, f"UpdateStackSet reused op1's id {op1_id!r}"
    op2 = _wait_stack_set_operation(cf, name, op2_id, {"SUCCEEDED", "FAILED", "STOPPED"}, timeout_s=600)
    assert op2["Status"] == "SUCCEEDED", f"op2 ended {op2['Status']!r}, expected 'SUCCEEDED'; op={op2!r}"
    assert op2["Action"] == "UPDATE", f"op2 Action is {op2['Action']!r}, expected 'UPDATE'"
    instance = cf.describe_stack_instance(StackSetName=name, StackInstanceAccount=account,
                                          StackInstanceRegion=region)["StackInstance"]
    assert instance["Status"] == "CURRENT", f"instance is {instance['Status']!r} after op2, expected 'CURRENT'"
    assert instance["StackId"] == stack_id, f"op2 replaced the instance stack: {instance['StackId']!r} != {stack_id!r}"
    ids = _logical_ids(cf, stack_id)
    assert ids == {"Anchor", "Gate", "Second"}, f"instance stack holds {sorted(ids)!r} after op2"



def _client_error(fn) -> dict:
    """Call fn(); return the botocore Error dict. Raises if fn unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _operations(cf, name: str) -> list:
    out = []
    for page in cf.get_paginator("list_stack_set_operations").paginate(StackSetName=name):
        out.extend(page.get("Summaries", []))
    return out


def _logical_ids(cf, stack_id: str) -> set:
    ids = set()
    for page in cf.get_paginator("list_stack_resources").paginate(StackName=stack_id):
        ids.update(r["LogicalResourceId"] for r in page["StackResourceSummaries"]
                   if r["ResourceStatus"] != "DELETE_COMPLETE")
    return ids


def _wait_stack_set_operation(cf, ss_name, op_id, targets, timeout_s=300, interval_s=4):
    deadline = time.monotonic() + timeout_s
    op = None
    while time.monotonic() < deadline:
        op = cf.describe_stack_set_operation(StackSetName=ss_name, OperationId=op_id)["StackSetOperation"]
        if op.get("Status") in targets:
            return op
        time.sleep(interval_s)
    raise AssertionError(f"stack set operation {op_id} did not reach {targets} (last={op.get('Status') if op else None!r})")


def _retry_on_malformed_principal(fn, attempts=20, delay_s=15.0):
    """IAM's eventual consistency: a just-created role ARN is briefly not a valid Principal."""
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
        lambda: iam.create_role(RoleName=exec_name, AssumeRolePolicyDocument=json.dumps(exec_trust))
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=exec_name))
    admin_policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    iam.attach_role_policy(RoleName=exec_name, PolicyArn=admin_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=exec_name, PolicyArn=admin_policy_arn))
    assume_policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Action": "sts:AssumeRole", "Resource": f"arn:aws:iam::{account_id}:role/{exec_name}"}]}
    iam.put_role_policy(RoleName=admin_name, PolicyName="AssumeExecRole", PolicyDocument=json.dumps(assume_policy))
    # IAM propagation exposes no pollable condition; the first use of the roles
    # (_start_barriered_instance) retries past it within a bound.
    return admin["Role"]["Arn"], exec_name


def _start_barriered_instance(cf, name, account, region, attempts=6, delay_s=20.0):
    """Start CreateStackInstances and wait until its instance stack is held at the Gate.

    Freshly created self-managed roles can fail the first operation for a while after IAM
    shows them (the instance lands FAILED naming the trust relationship), so that failure
    is retried within a bound after clearing the failed instance. Returns
    (operation id, instance stack id, ids of discarded operations).
    """
    discarded: set = set()
    last = None
    for _ in range(attempts):
        op_id = cf.create_stack_instances(StackSetName=name, Accounts=[account], Regions=[region])["OperationId"]
        deadline = time.monotonic() + 300.0
        while time.monotonic() < deadline:
            op = cf.describe_stack_set_operation(StackSetName=name, OperationId=op_id)["StackSetOperation"]
            stack_id = None
            try:
                stack_id = cf.describe_stack_instance(StackSetName=name, StackInstanceAccount=account,
                                                      StackInstanceRegion=region)["StackInstance"].get("StackId")
            except ClientError:
                pass
            if stack_id and op["Status"] == "RUNNING":
                try:
                    gate = cf.describe_stack_resource(StackName=stack_id, LogicalResourceId="Gate")[
                        "StackResourceDetail"]["ResourceStatus"]
                except ClientError:
                    gate = None
                if gate == "CREATE_IN_PROGRESS":
                    return op_id, stack_id, discarded
            if op["Status"] in ("SUCCEEDED", "FAILED", "STOPPED"):
                break
            time.sleep(3)
        else:
            raise AssertionError(f"operation {op_id} never held its instance at the Gate within 300s")
        instance = cf.describe_stack_instance(StackSetName=name, StackInstanceAccount=account,
                                              StackInstanceRegion=region)["StackInstance"]
        last = instance.get("StatusReason") or ""
        if op["Status"] != "FAILED" or "trust relationship" not in last.lower():
            raise AssertionError(f"operation {op_id} ended {op['Status']!r} before the Gate held; instance={instance!r}")
        discarded.add(op_id)
        del_id = cf.delete_stack_instances(StackSetName=name, Accounts=[account], Regions=[region],
                                           RetainStacks=False)["OperationId"]
        discarded.add(del_id)
        _wait_stack_set_operation(cf, name, del_id, {"SUCCEEDED", "FAILED", "STOPPED"}, timeout_s=300)
        time.sleep(delay_s)
    raise AssertionError(f"the stack instance never deployed past role propagation; last reason: {last!r}")


def _teardown_stack_set(cf, name):
    """Fail any still-open gate, let the running operation finish, delete instances, delete the set."""
    try:
        summaries = [s for p in cf.get_paginator("list_stack_instances").paginate(StackSetName=name)
                     for s in p.get("Summaries", [])]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "StackSetNotFoundException":
            return
        raise
    for s in summaries:
        try:
            if s.get("StackId") and cf.describe_stacks(StackName=s["StackId"])["Stacks"][0][
                    "StackStatus"].endswith("_IN_PROGRESS"):
                cf.signal_resource(StackName=s["StackId"], LogicalResourceId="Gate",
                                   UniqueId="sim2real-cleanup", Status="FAILURE")
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise
    try:
        for o in _operations(cf, name):
            if o["Status"] in ("RUNNING", "QUEUED", "STOPPING"):
                _wait_stack_set_operation(cf, name, o["OperationId"], {"SUCCEEDED", "FAILED", "STOPPED"}, timeout_s=600)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "OperationNotFoundException",
            "StackSetNotFoundException",
        ):
            raise
    if summaries:
        accounts = sorted({s["Account"] for s in summaries})
        regions = sorted({s["Region"] for s in summaries})
        try:
            op = cf.delete_stack_instances(
                StackSetName=name, Accounts=accounts, Regions=regions, RetainStacks=False,
                OperationPreferences={"RegionConcurrencyType": "PARALLEL",
                                      "MaxConcurrentCount": max(len(regions), 1)},
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
