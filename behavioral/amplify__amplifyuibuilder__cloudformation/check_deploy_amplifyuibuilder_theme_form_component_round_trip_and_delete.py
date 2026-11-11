"""deploy-amplifyuibuilder-theme-form-component-round-trip-and-delete."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-amplifyuibuilder-theme-form-component-round-trip-and-delete"
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

_ENV = "staging"
_ITEM_NOT_FOUND = ("404", "The item specified was not found")


def _parse_cfn_timestamp(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


def _template(app_name, theme_name, form_name, component_name, with_children=True):
    resources = {
        "App": {
            "Type": "AWS::Amplify::App",
            "Properties": {"Name": app_name, "Tags": [{"Key": "sim2real-app", "Value": app_name}]},
        },
    }
    outputs = {
        "AppRef": {"Value": {"Ref": "App"}},
        "AppIdAtt": {"Value": {"Fn::GetAtt": ["App", "AppId"]}},
    }
    if not with_children:
        return json.dumps({
            "AWSTemplateFormatVersion": "2010-09-09", "Resources": resources, "Outputs": outputs,
        })
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            **resources,
            "Theme": {
                "Type": "AWS::AmplifyUIBuilder::Theme",
                "Properties": {
                    "AppId": {"Fn::GetAtt": ["App", "AppId"]},
                    "EnvironmentName": _ENV,
                    "Name": theme_name,
                    "Values": [
                        {
                            "Key": "font",
                            "Value": {
                                "Children": [
                                    {"Key": "primary", "Value": {"Value": "Amazon Ember"}}
                                ]
                            },
                        }
                    ],
                },
            },
            "Form": {
                "Type": "AWS::AmplifyUIBuilder::Form",
                "Properties": {
                    "AppId": {"Fn::GetAtt": ["App", "AppId"]},
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
            },
            "Component": {
                "Type": "AWS::AmplifyUIBuilder::Component",
                "Properties": {
                    "AppId": {"Fn::GetAtt": ["App", "AppId"]},
                    "EnvironmentName": _ENV,
                    "Name": component_name,
                    "ComponentType": "Text",
                    "Properties": {"label": {"Value": "Hello World"}},
                    "Variants": [
                        {
                            "VariantValues": {"platform": "web"},
                            "Overrides": {"button-1": {"type": "style", "value": "red"}},
                        }
                    ],
                    "Overrides": {"button-1": {"type": "style", "value": "green"}},
                    "BindingProperties": {
                        "label": {
                            "Type": "String",
                            "BindingProperties": {"Field": "title", "Model": "Post"},
                            "DefaultValue": "untitled",
                        }
                    },
                },
            },
        },
        "Outputs": {
            **outputs,
            "ThemeRef": {"Value": {"Ref": "Theme"}},
            "ThemeId": {"Value": {"Fn::GetAtt": ["Theme", "Id"]}},
            "ThemeCreatedAt": {"Value": {"Fn::GetAtt": ["Theme", "CreatedAt"]}},
            "ThemeModifiedAt": {"Value": {"Fn::GetAtt": ["Theme", "ModifiedAt"]}},
            "FormRef": {"Value": {"Ref": "Form"}},
            "FormId": {"Value": {"Fn::GetAtt": ["Form", "Id"]}},
            "ComponentRef": {"Value": {"Ref": "Component"}},
            "ComponentId": {"Value": {"Fn::GetAtt": ["Component", "Id"]}},
            "ComponentCreatedAt": {"Value": {"Fn::GetAtt": ["Component", "CreatedAt"]}},
            "ComponentModifiedAt": {"Value": {"Fn::GetAtt": ["Component", "ModifiedAt"]}},
        },
    })


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Amplify App with a Theme, Form and Component reads back through both services.

    Refs match independent listings, every templated property round-trips, an update dropping the
    three children removes each from the same App, and deleting the stack removes the App.
    """
    cfn = ctx.client("cloudformation")
    amp = ctx.client("amplify")
    uib = ctx.client("amplifyuibuilder")

    app_name = ctx.unique_name("sim2real-cfnuib-app-")
    theme_name = ctx.unique_name("sim2real-cfnuib-theme-").replace("-", "")
    theme_name = theme_name[0].upper() + theme_name[1:]
    form_name = ctx.unique_name("sim2real-cfnuib-form-").replace("-", "")
    form_name = form_name[0].upper() + form_name[1:]
    component_name = ctx.unique_name("sim2real-cfnuib-comp-").replace("-", "")
    component_name = component_name[0].upper() + component_name[1:]

    stack = ctx.unique_name("sim2real-cfnuib-stack-")
    stack_id = create_stack(ctx, cfn, stack, _template(app_name, theme_name, form_name,
                                                       component_name))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)

    # --- App: Ref and GetAtt against an independent ListApps read by the templated name. ---
    apps = [a for a in paginate(amp, "list_apps", "apps") if a["name"] == app_name]
    assert len(apps) == 1, f"ListApps found {len(apps)} apps named {app_name!r}"
    app_id = apps[0]["appId"]
    assert (outputs["AppRef"], outputs["AppIdAtt"]) == (apps[0]["appArn"], app_id), (
        f"App Ref/AppId {(outputs['AppRef'], outputs['AppIdAtt'])!r} != listed "
        f"{(apps[0]['appArn'], app_id)!r}"
    )
    app = amp.get_app(appId=app_id)["app"]
    app_tags = {k: v for k, v in app.get("tags", {}).items() if not k.startswith("aws:")}
    assert (app["name"], app_tags) == (app_name, {"sim2real": stack, "sim2real-app": app_name}), (
        f"GetApp name/tags {(app['name'], app_tags)!r}"
    )

    def _listed_id(op, name):
        found = [e["id"] for e in paginate(uib, op, "entities", appId=app_id, environmentName=_ENV)
                 if e["name"] == name]
        assert len(found) == 1, f"{op} found {len(found)} entities named {name!r}"
        return found[0]

    theme_id = _listed_id("list_themes", theme_name)
    form_id = _listed_id("list_forms", form_name)
    component_id = _listed_id("list_components", component_name)
    got_ids = (outputs["ThemeId"], outputs["FormId"], outputs["ComponentId"])
    assert got_ids == (theme_id, form_id, component_id), (
        f"GetAtt Ids {got_ids!r} != listed {(theme_id, form_id, component_id)!r}"
    )

    # --- Theme ---
    theme = uib.get_theme(appId=app_id, environmentName=_ENV, id=theme_id)["theme"]
    expected_theme_ref = f"{app_id}|{_ENV}|{theme_id}"
    assert outputs["ThemeRef"] == expected_theme_ref, (
        f"Ref Theme was {outputs['ThemeRef']!r}, expected the primary identifier "
        f"{expected_theme_ref!r}"
    )
    assert theme["name"] == theme_name, (
        f"expected Theme Name {theme_name!r}, AmplifyUIBuilder reports {theme['name']!r}"
    )
    assert theme["values"] == [
        {"key": "font",
         "value": {"children": [{"key": "primary",
                                  "value": {"value": "Amazon Ember", "children": []}}]}}
    ], f"GetTheme returned values {theme['values']!r}, expected the declared nested Values"
    got_theme_created = _parse_cfn_timestamp(outputs["ThemeCreatedAt"])
    got_theme_modified = _parse_cfn_timestamp(outputs["ThemeModifiedAt"])
    assert got_theme_created == theme["createdAt"], (
        f"GetAtt Theme.CreatedAt was {got_theme_created!r}, AmplifyUIBuilder's own createdAt is "
        f"{theme['createdAt']!r}"
    )
    assert got_theme_modified == theme["modifiedAt"], (
        f"GetAtt Theme.ModifiedAt was {got_theme_modified!r}, AmplifyUIBuilder's own modifiedAt "
        f"is {theme['modifiedAt']!r}"
    )

    # --- Form ---
    form = uib.get_form(appId=app_id, environmentName=_ENV, id=form_id)["form"]
    expected_form_ref = f"{app_id}|{_ENV}|{form_id}"
    assert outputs["FormRef"] == expected_form_ref, (
        f"Ref Form was {outputs['FormRef']!r}, expected the primary identifier {expected_form_ref!r}"
    )
    assert form["name"] == form_name, f"expected Form Name {form_name!r}, got {form['name']!r}"
    assert form["dataType"] == {"dataSourceType": "DataStore", "dataTypeName": "Post"}, (
        f"expected dataType DataStore/Post, got {form['dataType']!r}"
    )
    assert form["formActionType"] == "create", (
        f"expected formActionType 'create', got {form['formActionType']!r}"
    )
    assert form["schemaVersion"] == "1.0", f"expected schemaVersion '1.0', got {form['schemaVersion']!r}"
    assert form["fields"]["title"]["label"] == "Title", (
        f"expected fields.title.label 'Title', got {form['fields']['title'].get('label')!r}"
    )
    assert form["style"]["horizontalGap"]["value"] == "8px", (
        f"expected style.horizontalGap.value '8px', got {form['style']['horizontalGap'].get('value')!r}"
    )
    assert form["style"]["verticalGap"]["value"] == "8px", (
        f"expected style.verticalGap.value '8px', got {form['style']['verticalGap'].get('value')!r}"
    )
    assert form["style"]["outerPadding"]["value"] == "16px", (
        f"expected style.outerPadding.value '16px', got {form['style']['outerPadding'].get('value')!r}"
    )
    assert form["sectionalElements"]["heading1"]["type"] == "Heading", (
        f"expected sectionalElements.heading1.type 'Heading', got "
        f"{form['sectionalElements']['heading1'].get('type')!r}"
    )
    assert form["sectionalElements"]["heading1"]["level"] == 2, (
        f"expected sectionalElements.heading1.level 2, got "
        f"{form['sectionalElements']['heading1'].get('level')!r}"
    )
    assert form["sectionalElements"]["heading1"]["text"] == "New Post", (
        f"expected sectionalElements.heading1.text 'New Post', got "
        f"{form['sectionalElements']['heading1'].get('text')!r}"
    )

    # --- Component ---
    component = uib.get_component(appId=app_id, environmentName=_ENV, id=component_id)["component"]
    expected_component_ref = f"{app_id}|{_ENV}|{component_id}"
    assert outputs["ComponentRef"] == expected_component_ref, (
        f"Ref Component was {outputs['ComponentRef']!r}, expected the primary identifier "
        f"{expected_component_ref!r}"
    )
    assert component["name"] == component_name, (
        f"expected Name {component_name!r}, got {component['name']!r}"
    )
    assert component["componentType"] == "Text", (
        f"expected componentType 'Text', got {component['componentType']!r}"
    )
    assert component["properties"]["label"]["value"] == "Hello World", (
        f"expected properties.label.value 'Hello World', got "
        f"{component['properties']['label'].get('value')!r}"
    )
    assert component["variants"][0]["variantValues"] == {"platform": "web"}, (
        f"expected variants[0].variantValues {{'platform': 'web'}}, got "
        f"{component['variants'][0].get('variantValues')!r}"
    )
    assert component["variants"][0]["overrides"]["button-1"] == {"type": "style", "value": "red"}, (
        f"expected variants[0].overrides['button-1'] {{'type': 'style', 'value': 'red'}}, got "
        f"{component['variants'][0]['overrides'].get('button-1')!r}"
    )
    assert component["overrides"]["button-1"] == {"type": "style", "value": "green"}, (
        f"expected overrides['button-1'] {{'type': 'style', 'value': 'green'}}, got "
        f"{component['overrides'].get('button-1')!r}"
    )
    assert component["bindingProperties"]["label"]["bindingProperties"]["field"] == "title", (
        f"expected bindingProperties.label.bindingProperties.field 'title', got "
        f"{component['bindingProperties']['label']['bindingProperties'].get('field')!r}"
    )
    assert component["bindingProperties"]["label"]["bindingProperties"]["model"] == "Post", (
        f"expected bindingProperties.label.bindingProperties.model 'Post', got "
        f"{component['bindingProperties']['label']['bindingProperties'].get('model')!r}"
    )
    assert component["bindingProperties"]["label"]["defaultValue"] == "untitled", (
        f"expected bindingProperties.label.defaultValue 'untitled', got "
        f"{component['bindingProperties']['label'].get('defaultValue')!r}"
    )
    got_component_created = _parse_cfn_timestamp(outputs["ComponentCreatedAt"])
    got_component_modified = _parse_cfn_timestamp(outputs["ComponentModifiedAt"])
    assert got_component_created == component["createdAt"], (
        f"GetAtt Component.CreatedAt was {got_component_created!r}, AmplifyUIBuilder's own "
        f"createdAt is {component['createdAt']!r}"
    )
    assert got_component_modified == component["modifiedAt"], (
        f"GetAtt Component.ModifiedAt was {got_component_modified!r}, AmplifyUIBuilder's own "
        f"modifiedAt is {component['modifiedAt']!r}"
    )

    # Children before the parent: an update keeping only the App removes all three from the SAME
    # App (createTime unchanged), each answering its own NotFound while the App still answers.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(
        app_name, theme_name, form_name, component_name, with_children=False))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"child-removing update ended {status!r}"
    for read in (lambda: uib.get_theme(appId=app_id, environmentName=_ENV, id=theme_id),
                 lambda: uib.get_form(appId=app_id, environmentName=_ENV, id=form_id),
                 lambda: uib.get_component(appId=app_id, environmentName=_ENV, id=component_id)):
        until_raises(read)
        expect_error(read, *_ITEM_NOT_FOUND)
    after = amp.get_app(appId=app_id)["app"]
    assert after["createTime"] == app["createTime"], (
        f"App createTime changed across the update: {after['createTime']!r}"
    )

    delete_stack(cfn, stack_id)
    until_raises(lambda: amp.get_app(appId=app_id))
    app_gone = ("NotFoundException", f"App {app_id} not found.")
    expect_error(lambda: amp.get_app(appId=app_id), *app_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
