"""deploy-amplifyuibuilder-form-invalid-name-rejected-and-rolled-back."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "deploy-amplifyuibuilder-form-invalid-name-rejected-and-rolled-back"
GROUP = "deploy"
SERVICES = ["amplify", "amplifyuibuilder", "cloudformation"]

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

_ENV = "staging"
_REJECTED = (
    "Entity name is not a valid name "
    "(Service: AmplifyUiBuilder, Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)",
    "InternalFailure",
)


def _form(app_id, form_name):
    """The Form resource; the control and the rejected stack differ only in ``form_name``."""
    return {
        "Type": "AWS::AmplifyUIBuilder::Form",
        "Properties": {
            "AppId": app_id,
            "EnvironmentName": _ENV,
            "Name": form_name,
            "DataType": {"DataSourceType": "DataStore", "DataTypeName": "Post"},
            "FormActionType": "create",
            "SchemaVersion": "1.0",
            "Fields": {"title": {"Label": "Title"}},
            "Style": {
                "HorizontalGap": {"Value": "8px"},
                "VerticalGap": {"Value": "8px"},
                "OuterPadding": {"Value": "16px"},
            },
            "SectionalElements": {
                "heading1": {"Type": "Heading", "Level": 2, "Text": "New Post"}
            },
        },
    }


def _control_template(app_name, form_name):
    """The App and a Form under it."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "App": {"Type": "AWS::Amplify::App", "Properties": {
                "Name": app_name, "Tags": [{"Key": "sim2real-app", "Value": app_name}]}},
            "Form": _form({"Fn::GetAtt": ["App", "AppId"]}, form_name),
        },
        "Outputs": {
            "AppIdAtt": {"Value": {"Fn::GetAtt": ["App", "AppId"]}},
            "FormId": {"Value": {"Fn::GetAtt": ["Form", "Id"]}},
        },
    })


def _form_template(app_id, form_name):
    """The same Form under the control's App."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Form": _form(app_id, form_name)},
    })


def _forms_named(uib, app_id, name):
    return [f for f in paginate(uib, "list_forms", "entities", appId=app_id, environmentName=_ENV)
            if f["name"] == name]


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AmplifyUIBuilder Form whose Name starts lowercase is refused and rolls back.

    AmplifyUIBuilder rejects the name and lists no such form under the App, while the same Form
    with the name capitalised deploys and reads back.
    """
    cfn = ctx.client("cloudformation")
    amp = ctx.client("amplify")
    uib = ctx.client("amplifyuibuilder")
    app_name = ctx.unique_name("sim2real-cfnuib-negapp-")
    stem = ctx.unique_name("sim2real-cfnuib-form-").replace("-", "")
    good_form, bad_form = stem[0].upper() + stem[1:], stem

    # Positive control: the App and the Form with a valid (capitalised) Name.
    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-cfnuib-formok-stack-"),
                           _control_template(app_name, good_form))
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cfn, good_id))!r}"
    )
    out = stack_outputs(cfn, good_id)
    apps = [a for a in paginate(amp, "list_apps", "apps") if a["name"] == app_name]
    assert [a["appId"] for a in apps] == [out["AppIdAtt"]], (
        f"ListApps found {len(apps)} apps named {app_name!r} for AppId {out['AppIdAtt']!r}"
    )
    app_id = apps[0]["appId"]
    listed = _forms_named(uib, app_id, good_form)
    assert [f["id"] for f in listed] == [out["FormId"]], (
        f"ListForms found {listed!r} for the control form {good_form!r}"
    )
    form = uib.get_form(appId=app_id, environmentName=_ENV, id=out["FormId"])["form"]
    got = (form["name"], form["dataType"], form["formActionType"], form["schemaVersion"])
    want = (good_form, {"dataSourceType": "DataStore", "dataTypeName": "Post"}, "create", "1.0")
    assert got == want, f"control form reads {got!r}, expected {want!r}"

    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-cfnuib-formbad-stack-"),
                          _form_template(app_id, bad_form))
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    reason = failed_reason(stack_events(cfn, bad_id), "Form")
    got_reason = handler_reason(reason, ctx.account, bad_form)
    assert got_reason == _REJECTED, f"handler reason {got_reason!r}, expected {_REJECTED!r}"

    # Rollback absence through AmplifyUIBuilder under the live App, BEFORE this check deletes.
    left = _forms_named(uib, app_id, bad_form)
    assert left == [], f"the rolled-back form is listed: {left!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
