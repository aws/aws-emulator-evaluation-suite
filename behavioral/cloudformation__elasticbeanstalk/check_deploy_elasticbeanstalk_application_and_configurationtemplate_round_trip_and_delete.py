"""deploy-elasticbeanstalk-application-and-configurationtemplate-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-elasticbeanstalk-application-and-configurationtemplate-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "elasticbeanstalk"]

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

_OPTION = ("aws:autoscaling:launchconfiguration", "InstanceType", "t3.micro")


def _pick_solution_stack(eb) -> str:
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    picked = [s for s in stacks if "Amazon Linux 2" in s and "Python" in s]
    assert picked, f"no Amazon Linux 2 Python solution stack among {len(stacks)} stacks"
    return picked[0]


def _template(app_name, app_description, solution_stack, with_template=True):
    resources = {"App": {"Type": "AWS::ElasticBeanstalk::Application",
                         "Properties": {"ApplicationName": app_name,
                                        "Description": app_description}}}
    outputs = {"AppRef": {"Value": {"Ref": "App"}}}
    if with_template:
        resources["ConfigTemplate"] = {
            "Type": "AWS::ElasticBeanstalk::ConfigurationTemplate", "Properties": {
                "ApplicationName": {"Ref": "App"},
                "SolutionStackName": solution_stack,
                "OptionSettings": [{"Namespace": _OPTION[0], "OptionName": _OPTION[1],
                                    "Value": _OPTION[2]}],
            }}
        outputs["ConfigTemplateRef"] = {"Value": {"Ref": "ConfigTemplate"}}
        outputs["ConfigTemplateNameAtt"] = {
            "Value": {"Fn::GetAtt": ["ConfigTemplate", "TemplateName"]}}
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources,
                       "Outputs": outputs})


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Elastic Beanstalk application and configuration template read back as set.

    An update dropping the template removes it from the still-present application, and deleting
    the stack removes the application.
    """
    cf = ctx.client("cloudformation")
    eb = ctx.client("elasticbeanstalk")
    stack = ctx.unique_name("sim2real-cfneb-stack-")
    app_name = ctx.unique_name("sim2real-cfneb-app-")
    app_description = ctx.unique_name("sim2real-cfneb-appdesc-")
    solution_stack = _pick_solution_stack(eb)

    stack_id = create_stack(ctx, cf, stack, _template(app_name, app_description, solution_stack))
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)

    # Application Ref against DescribeApplications by the declared name; the template's Ref and
    # GetAtt against the application's own list of configuration templates.
    apps = eb.describe_applications(ApplicationNames=[app_name])["Applications"]
    got_apps = [(a["ApplicationName"], a.get("Description"), a.get("ConfigurationTemplates"))
                for a in apps]
    want_apps = [(out["AppRef"], app_description, [out["ConfigTemplateRef"]])]
    assert got_apps == want_apps, f"DescribeApplications {got_apps!r}, expected {want_apps!r}"
    assert out["ConfigTemplateNameAtt"] == out["ConfigTemplateRef"], (
        f"GetAtt TemplateName {out['ConfigTemplateNameAtt']!r}, Ref {out['ConfigTemplateRef']!r}"
    )
    settings = eb.describe_configuration_settings(
        ApplicationName=app_name, TemplateName=out["ConfigTemplateRef"])["ConfigurationSettings"]
    got = [(s["ApplicationName"], s["TemplateName"], s["SolutionStackName"],
            {(o["Namespace"], o["OptionName"]): o.get("Value") for o in s["OptionSettings"]}
            .get(_OPTION[:2])) for s in settings]
    assert got == [(app_name, out["ConfigTemplateRef"], solution_stack, _OPTION[2])], (
        f"DescribeConfigurationSettings {got!r}"
    )

    # The template alone: an update dropping it empties the application's template list.
    cf.update_stack(StackName=stack_id,
                    TemplateBody=_template(app_name, app_description, solution_stack, False))
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"template-removing update ended {status!r}"
    kept = [(a["ApplicationName"], a.get("ConfigurationTemplates", []))
            for a in eb.describe_applications(ApplicationNames=[app_name])["Applications"]]
    assert kept == [(app_name, [])], f"after dropping the template the application reads {kept!r}"

    delete_stack(cf, stack_id)
    gone = eb.describe_applications(ApplicationNames=[app_name])["Applications"]
    assert gone == [], f"DescribeApplications still reports the deleted application: {gone!r}"
    not_found = ("InvalidParameterValue", f"No Application named '{app_name}' found.")
    expect_error(
        lambda: eb.describe_configuration_settings(
        ApplicationName=app_name, TemplateName=out["ConfigTemplateRef"]),
        *not_found,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
