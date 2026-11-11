"""deploy-cfn-emrserverless-application-invalid-release-label-rejected."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "deploy-cfn-emrserverless-application-invalid-release-label-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "emr-serverless"]

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


# ---- Check-specific: the template, then run(). ----

_REJECTED = (
    "Invalid request provided: Type is not supported for the release label or release label "
    "does not exist (Service: EmrServerless, Status Code: 400, Request ID: <id>) "
    "(SDK Attempt Count: <n>)",
    "InvalidRequest",
)


def _template(name: str, *, release_label: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Application": {
                "Type": "AWS::EMRServerless::Application",
                "Properties": {
                    "Name": name,
                    "ReleaseLabel": release_label,
                    "Type": "SPARK",
                    "AutoStartConfiguration": {"Enabled": False},
                },
            },
        },
    })


def _list_all_names(emrs) -> set:
    return {a["name"] for a in paginate(emrs, "list_applications", "applications")}


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation EMR Serverless application with a well-formed but non-existent release
    label never creates the application, and the stack rolls back with the resource handler's
    exact validation message; a sibling stack with a valid release label deploys successfully."""
    cfn = ctx.client("cloudformation")
    emrs = ctx.client("emr-serverless")

    control_stack = ctx.unique_name("sim2real-cfnemrsctl-")
    broken_stack = ctx.unique_name("sim2real-cfnemrsbrk-")
    control_name = ctx.unique_name("sim2real-cfnemrsctl-app-")
    broken_name = ctx.unique_name("sim2real-cfnemrsbrk-app-")
    bogus_release = "emr-0.0.0-does-not-exist"

    # Both launched before either is awaited, so neither outcome is an artefact of ordering.
    control_id = create_stack(ctx, cfn, control_stack,
                              _template(control_name, release_label="emr-7.9.0"))
    broken_id = create_stack(ctx, cfn, broken_stack,
                             _template(broken_name, release_label=bogus_release))

    ctl_status = wait_stack(cfn, control_id)
    assert ctl_status == "CREATE_COMPLETE", (
        f"control stack settled at {ctl_status!r}: "
        f"{decisive_rows(stack_events(cfn, control_id))!r}"
    )
    ctl_physical_id = cfn.describe_stack_resource(
        StackName=control_id, LogicalResourceId="Application"
    )["StackResourceDetail"]["PhysicalResourceId"]
    ctl_app = emrs.get_application(applicationId=ctl_physical_id)["application"]
    assert ctl_app["state"] == "CREATED", f"control application state was {ctl_app['state']!r}"
    got_props = (ctl_app["name"], ctl_app["releaseLabel"], ctl_app["type"],
                 ctl_app["autoStartConfiguration"])
    want_props = (control_name, "emr-7.9.0", "Spark", {"enabled": False})
    assert got_props == want_props, (
        f"control application (name, releaseLabel, type, autoStartConfiguration): expected "
        f"{want_props!r}, EMR Serverless reports {got_props!r}"
    )

    brk_status = wait_stack(cfn, broken_id)
    assert brk_status == "ROLLBACK_COMPLETE", (
        f"stack with non-existent release label {bogus_release!r} settled at {brk_status!r}, "
        f"expected ROLLBACK_COMPLETE"
    )

    events = stack_events(cfn, broken_id)
    got_error = handler_reason(failed_reason(events, "Application"), ctx.account, broken_name)
    assert got_error == _REJECTED, (
        f"Application CREATE_FAILED reason: expected {_REJECTED!r}, got {got_error!r}"
    )

    created = [e for e in events
               if e["LogicalResourceId"] == "Application" and e["ResourceStatus"] == "CREATE_COMPLETE"]
    assert created == [], (
        f"the Application must never reach CREATE_COMPLETE on the broken stack, but it did: {created!r}"
    )
    # Effect absent through EMR Serverless itself: no application carries the broken template's name.
    names = _list_all_names(emrs)
    assert broken_name not in names, (
        f"CloudFormation rolled back, but ListApplications still shows {broken_name!r}"
    )

    delete_stack(cfn, broken_id)
    delete_stack(cfn, control_id)
    ctl_gone_state = emrs.get_application(applicationId=ctl_physical_id)["application"]["state"]
    assert ctl_gone_state == "TERMINATED", (
        f"GetApplication for the deleted control stack's application reported {ctl_gone_state!r}, "
        f"expected TERMINATED"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
