"""deploy-service-dnsconfig-in-http-namespace-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-service-dnsconfig-in-http-namespace-rejected"
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
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


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


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


def handler_reason(reason, account, *names):
    """``(masked message, HandlerErrorCode)`` of a registry-handler reason; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return masked(m["message"], account, *names), m["code"]


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

_REJECTED = (
    "When you create a service using a namespace that has a type of HTTP, you can't include a "
    "DnsConfig element. (Service: ServiceDiscovery, Status Code: 400, Request ID: <id>) "
    "(SDK Attempt Count: <n>)",
    "InvalidRequest",
)


def _namespace_and_service_template(ns_name: str, svc_name: str, *, with_dns_config: bool) -> str:
    service_props = {"Name": svc_name, "NamespaceId": {"Ref": "Namespace"}}
    if with_dns_config:
        service_props["DnsConfig"] = {
            "DnsRecords": [{"Type": "A", "TTL": 60}],
            "RoutingPolicy": "MULTIVALUE",
        }
    return json.dumps({
        "Resources": {
            "Namespace": {
                "Type": "AWS::ServiceDiscovery::HttpNamespace",
                "Properties": {"Name": ns_name},
            },
            "Service": {
                "Type": "AWS::ServiceDiscovery::Service",
                "Properties": service_props,
            },
        },
        "Outputs": {
            "NamespaceRef": {"Value": {"Ref": "Namespace"}},
            "ServiceRef": {"Value": {"Ref": "Service"}},
        },
    })


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A Service declaring DnsConfig inside an HttpNamespace rolls its stack back with the exact
    CreateService refusal and Cloud Map holds no such service; the same template without DnsConfig
    (an HTTP namespace admits no valid DnsConfig) deploys and reads back."""
    cfn = ctx.client("cloudformation")
    sd = ctx.client("servicediscovery")
    good_ns_name = ctx.unique_name("sim2real-behav-cfn-sdgood-")
    good_svc_name = ctx.unique_name("sim2real-behav-cfn-sdgood-")
    bad_ns_name = ctx.unique_name("sim2real-behav-cfn-sdbad-")
    bad_svc_name = ctx.unique_name("sim2real-behav-cfn-sdbad-")

    # Both stacks are created before either is waited on: the namespaces provision in parallel.
    bad_id = create_stack(
        ctx, cfn, ctx.unique_name("sim2real-behav-cfn-sdbad-"),
        _namespace_and_service_template(bad_ns_name, bad_svc_name, with_dns_config=True),
    )
    good_id = create_stack(
        ctx, cfn, ctx.unique_name("sim2real-behav-cfn-sdgood-"),
        _namespace_and_service_template(good_ns_name, good_svc_name, with_dns_config=False),
    )

    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    events = stack_events(cfn, bad_id)
    got = handler_reason(failed_reason(events, "Service"), ctx.account, bad_svc_name, bad_ns_name)
    assert got == _REJECTED, f"handler reason {got!r}, expected {_REJECTED!r}"
    # Rollback absence through Cloud Map before any delete: no service by the rejected name, and
    # the namespace the rollback removed answers NamespaceNotFound.
    names = {s["Name"] for s in paginate(sd, "list_services", "Services")}
    assert bad_svc_name not in names, f"Cloud Map lists the rejected service {bad_svc_name!r}"
    ns_ids = [e["PhysicalResourceId"] for e in events
              if e["LogicalResourceId"] == "Namespace" and e["ResourceStatus"] == "CREATE_COMPLETE"]
    assert len(ns_ids) == 1, f"expected the namespace created once, got {ns_ids!r}"
    gone = ("NamespaceNotFound", "")
    expect_error(lambda: sd.get_namespace(Id=ns_ids[0]), *gone)

    # Positive control: the same template without DnsConfig deploys and reads back.
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", f"control stack ended {status!r}"
    outputs = stack_outputs(cfn, good_id)
    listed = [(s["Id"], s["Name"]) for s in paginate(
        sd, "list_services", "Services",
        Filters=[{"Name": "NAMESPACE_ID", "Values": [outputs["NamespaceRef"]], "Condition": "EQ"}])]
    assert listed == [(outputs["ServiceRef"], good_svc_name)], f"control services {listed!r}"
    ns_got = sd.get_namespace(Id=outputs["NamespaceRef"])["Namespace"]
    got = (ns_got["Name"], ns_got["Type"])
    assert got == (good_ns_name, "HTTP"), f"control namespace reads {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
