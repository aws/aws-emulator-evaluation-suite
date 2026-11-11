"""deploy-resiliencehubv2-service-and-servicefunction-round-trip-then-child-and-stack-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = ("deploy-resiliencehubv2-service-and-servicefunction-round-trip-"
         "then-child-and-stack-delete")
GROUP = "deploy"
SERVICES = ["cloudformation", "resiliencehubv2"]

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

_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "resiliencehub.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
}


def _template(svc_name, region, with_sf, sf_name=None, sf_criticality=None):
    resources = {
        "InvokerRole": {"Type": "AWS::IAM::Role", "Properties": {
            "AssumeRolePolicyDocument": _TRUST,
        }},
        "Svc": {"Type": "AWS::ResilienceHubV2::Service", "Properties": {
            "Name": svc_name, "Regions": [region], "DependencyDiscovery": "DISABLED",
            "PermissionModel": {"InvokerRoleName": {"Ref": "InvokerRole"}},
        }},
    }
    outputs = {
        "SvcArn": {"Value": {"Ref": "Svc"}},
        "RoleName": {"Value": {"Ref": "InvokerRole"}},
    }
    if with_sf:
        resources["SF"] = {"Type": "AWS::ResilienceHubV2::ServiceFunction", "Properties": {
            "ServiceArn": {"Ref": "Svc"}, "Name": sf_name, "Criticality": sf_criticality,
        }}
        outputs["SFRef"] = {"Value": {"Ref": "SF"}}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": resources,
        "Outputs": outputs,
    })


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation ResilienceHubV2 Service and child ServiceFunction read back through
    ResilienceHubV2 with their declared properties; dropping the ServiceFunction in an update
    removes only it, and deleting the stack removes the Service.
    """
    cf = ctx.client("cloudformation")
    rhv2 = ctx.client("resiliencehubv2")
    stack = ctx.unique_name("sim2real-rhv2-svcsf-")
    svc_name = ctx.unique_name("sim2real-rhv2-svc-")
    sf_name = ctx.unique_name("sim2real-rhv2-sf-")

    stack_id = create_stack(
        ctx, cf, stack, _template(svc_name, ctx.region, True, sf_name, "PRIMARY"),
        Capabilities=["CAPABILITY_IAM"],
    )
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {stack_events(cf, stack_id)!r}"
    )
    out = stack_outputs(cf, stack_id)
    svc_arn, role_name, sf_ref = out["SvcArn"], out["RoleName"], out["SFRef"]
    sf_svc_half, sf_id = sf_ref.split("|", 1)
    assert sf_svc_half == svc_arn, f"ServiceFunction Ref {sf_ref!r} does not embed {svc_arn!r}"

    svc = rhv2.get_service(serviceArn=svc_arn)["service"]
    assert (svc["name"], svc["regions"]) == (svc_name, [ctx.region]), (
        f"GetService name/regions {(svc['name'], svc['regions'])!r} != "
        f"{(svc_name, [ctx.region])!r}"
    )
    assert svc["dependencyDiscovery"]["status"] == "DISABLED", (
        f"GetService dependencyDiscovery.status {svc['dependencyDiscovery']['status']!r} != "
        f"'DISABLED'"
    )
    assert svc["permissionModel"]["invokerRoleName"] == role_name, (
        f"GetService permissionModel.invokerRoleName {svc['permissionModel']['invokerRoleName']!r}"
        f" != {role_name!r}"
    )
    created_at = svc["createdAt"]
    svc_tags = {k: v for k, v in rhv2.list_tags_for_resource(resourceArn=svc_arn)["tags"].items()
            if not k.startswith("aws:")}
    assert svc_tags == {"sim2real": stack}, f"Service tags {svc_tags!r}, expected the stack tag"

    services = {s["name"]: s for s in paginate(rhv2, "list_services", "serviceSummaries")}
    assert svc_name in services, f"ListServices did not include {svc_name!r}"
    assert services[svc_name]["serviceArn"] == svc_arn, (
        f"ListServices entry for {svc_name!r} has ARN {services[svc_name]['serviceArn']!r}, "
        f"expected {svc_arn!r}"
    )

    sfs = paginate(rhv2, "list_service_functions", "serviceFunctions", serviceArn=svc_arn)
    assert {f["serviceFunctionId"] for f in sfs} == {sf_id}, (
        f"ListServiceFunctions(serviceArn={svc_arn!r}) returned {sfs!r}, expected only {sf_id!r}"
    )
    sf = sfs[0]
    assert (sf["name"], sf["criticality"]) == (sf_name, "PRIMARY"), (
        f"ServiceFunction name/criticality {(sf['name'], sf['criticality'])!r} != "
        f"{(sf_name, 'PRIMARY')!r}"
    )

    # Child before parent: dropping the ServiceFunction removes only it; the Service (same
    # createdAt) survives, so it was updated in place rather than replaced.
    cf.update_stack(
        StackName=stack_id, TemplateBody=_template(svc_name, ctx.region, False),
        Capabilities=["CAPABILITY_IAM"],
    )
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"ServiceFunction-dropping update ended {status!r}"

    sfs_after = paginate(rhv2, "list_service_functions", "serviceFunctions", serviceArn=svc_arn)
    assert sfs_after == [], f"ListServiceFunctions still reports {sfs_after!r} after the update"
    svc_after_update = rhv2.get_service(serviceArn=svc_arn)["service"]
    assert svc_after_update["createdAt"] == created_at, (
        f"Service createdAt changed from {created_at!r} to {svc_after_update['createdAt']!r}; "
        f"it was replaced rather than updated in place"
    )

    delete_stack(cf, stack_id)
    service_id = svc_arn.rsplit(":", 1)[-1]
    gone = ("ResourceNotFoundException", f"Service not found: {service_id}")
    expect_error(lambda: rhv2.get_service(serviceArn=svc_arn), *gone)
    services_after = {s["name"] for s in paginate(rhv2, "list_services", "serviceSummaries")}
    assert svc_name not in services_after, f"ListServices still lists the deleted {svc_name!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
