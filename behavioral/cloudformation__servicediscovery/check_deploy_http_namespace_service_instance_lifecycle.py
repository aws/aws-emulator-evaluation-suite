"""deploy-http-namespace-service-instance-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-http-namespace-service-instance-lifecycle"
GROUP = "deploy"
SERVICES = ["cloudformation", "servicediscovery"]

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


def until_raises(fn, timeout_s=90.0):
    """Poll ``fn()`` every 2 s until it raises a ClientError (an eventually consistent delete).

    Grade the error afterwards with expect_error; a success past the deadline fails.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError:
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"still answering after {timeout_s:.0f}s: {result!r}")
        time.sleep(2)


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

def _template(ns_name, svc_name, instance_id, with_instance=True):
    resources = {
        "Namespace": {
            "Type": "AWS::ServiceDiscovery::HttpNamespace",
            "Properties": {"Name": ns_name},
        },
        "Service": {
            "Type": "AWS::ServiceDiscovery::Service",
            "Properties": {"Name": svc_name, "NamespaceId": {"Ref": "Namespace"}},
        },
    }
    outputs = {
        "NamespaceRef": {"Value": {"Ref": "Namespace"}},
        "NamespaceArn": {"Value": {"Fn::GetAtt": ["Namespace", "Arn"]}},
        "ServiceRef": {"Value": {"Ref": "Service"}},
        "ServiceArn": {"Value": {"Fn::GetAtt": ["Service", "Arn"]}},
    }
    if with_instance:
        resources["Instance"] = {
            "Type": "AWS::ServiceDiscovery::Instance",
            "Properties": {
                "InstanceId": instance_id,
                "ServiceId": {"Ref": "Service"},
                "InstanceAttributes": {"AWS_INSTANCE_IPV4": "192.0.2.44"},
            },
        }
        outputs["InstanceRef"] = {"Value": {"Ref": "Instance"}}
    return json.dumps({"Resources": resources, "Outputs": outputs})


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation stack provisions an HttpNamespace, a Service and an Instance; each Ref is
    the id Cloud Map lists, GetAtt Arn matches its records, an update dropping the Instance
    deregisters it while its Service answers, and deleting the stack removes the rest."""
    cfn = ctx.client("cloudformation")
    sd = ctx.client("servicediscovery")

    ns_name = ctx.unique_name("sim2real-behav-cfnhttp-")
    svc_name = ctx.unique_name("sim2real-behav-cfnsvc-")
    instance_id = ctx.unique_name("sim2real-behav-cfninst-")

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-cfn-sdhttp-"),
                            _template(ns_name, svc_name, instance_id))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    namespace_id = outputs["NamespaceRef"]
    service_id = outputs["ServiceRef"]

    # Each Ref against an independent list filtered to the template's own name or parent.
    listed = [(n["Id"], n["Arn"], n["Type"]) for n in paginate(
        sd, "list_namespaces", "Namespaces",
        Filters=[{"Name": "NAME", "Values": [ns_name], "Condition": "EQ"}])]
    assert listed == [(namespace_id, outputs["NamespaceArn"], "HTTP")], (
        f"ListNamespaces {listed!r} for Ref {namespace_id!r}"
    )
    listed = [(s["Id"], s["Arn"], s["Name"]) for s in paginate(
        sd, "list_services", "Services",
        Filters=[{"Name": "NAMESPACE_ID", "Values": [namespace_id], "Condition": "EQ"}])]
    assert listed == [(service_id, outputs["ServiceArn"], svc_name)], (
        f"ListServices {listed!r} for Ref {service_id!r}"
    )
    listed = [(i["Id"], i.get("Attributes")) for i in paginate(
        sd, "list_instances", "Instances", ServiceId=service_id)]
    want = [(instance_id, {"AWS_INSTANCE_IPV4": "192.0.2.44"})]
    assert listed == want, f"ListInstances {listed!r}, expected {want!r}"
    assert outputs["InstanceRef"] == instance_id, (
        f"Instance Ref {outputs['InstanceRef']!r}, expected the InstanceId {instance_id!r}"
    )
    ns_got = sd.get_namespace(Id=namespace_id)["Namespace"]
    assert ns_got["Name"] == ns_name, f"GetNamespace Name {ns_got['Name']!r} != {ns_name!r}"

    # Child first: the update drops the Instance; its own NotFound while the Service answers.
    cfn.update_stack(StackName=stack_id,
                     TemplateBody=_template(ns_name, svc_name, instance_id, with_instance=False))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"instance-dropping update ended {status!r}"
    until_raises(lambda: sd.get_instance(ServiceId=service_id, InstanceId=instance_id))
    gone = ("InstanceNotFound", instance_id)
    expect_error(lambda: sd.get_instance(ServiceId=service_id, InstanceId=instance_id), *gone)
    svc_got = sd.get_service(Id=service_id)["Service"]
    assert svc_got["Id"] == service_id, f"GetService after the update reads {svc_got!r}"

    delete_stack(cfn, stack_id)
    gone = ("ServiceNotFound", "")
    expect_error(lambda: sd.get_service(Id=service_id), *gone)
    gone = ("NamespaceNotFound", "")
    expect_error(lambda: sd.get_namespace(Id=namespace_id), *gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
