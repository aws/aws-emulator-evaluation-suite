"""cfn-elasticbeanstalk-application-in-place-update-retained-replacement-then-not-found."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-elasticbeanstalk-application-in-place-update-retained-replacement-then-not-found"
GROUP = "deploy"
SERVICES = ["cloudformation", "elasticbeanstalk"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
#: An application change can take a moment to reach every read.
_PROPAGATE_CAP_S = 60.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

#: The option every configuration template the check adds by API sets.
_OPTION = ("aws:autoscaling:launchconfiguration", "InstanceType", "t3.micro")


def _not_found(app_name: str) -> tuple[str, str]:
    """Elastic Beanstalk's refusal of a read under an application that no longer exists."""
    return "InvalidParameterValue", f"No Application named '{app_name}' found."


def _template(app_name: str, description: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Application": {
                    "Type": "AWS::ElasticBeanstalk::Application",
                    # ApplicationName is create-only, so changing it replaces the application.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {"ApplicationName": app_name, "Description": description},
                },
            },
            "Outputs": {"ApplicationName": {"Value": {"Ref": "Application"}}},
        }
    )


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Beanstalk application reads back as templated and hosts a config template.

    A Description change keeps the application; an ApplicationName change under
    UpdateReplacePolicy Retain keeps the old one and its template; delete: InvalidParameterValue.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-elasticbeanstalk-application.html
    """
    cfn = ctx.client("cloudformation")
    eb = ctx.client("elasticbeanstalk")
    first = ctx.unique_name("sim2real-cfnebapp-a-")
    second = ctx.unique_name("sim2real-cfnebapp-b-")
    stack_name = ctx.unique_name("sim2real-cfnebapp-stack-")
    template_name = ctx.unique_name("sim2real-cfnebapp-tmpl-")
    solution_stack = _solution_stack(eb)
    ref = {"stack": stack_name}

    # The replaced application is retained, so it outlives the stack and needs its own teardown;
    # deleting it also deletes the configuration template the check adds to it.
    ctx.on_cleanup(lambda: _delete_application(eb, first))
    # Teardown waits on its own caps (ctx=None): the body's deadline does not bound cleanup.
    ctx.on_cleanup(lambda: _teardown_stack(None, cfn, ref))

    # ---- 1. create: CloudFormation's view, Elastic Beanstalk's view, a template it hosts
    ref["stack"] = cfn.create_stack(
        StackName=stack_name, TemplateBody=_template(first, "first description"), Tags=_TAGS
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    partition = ref["stack"].split(":")[1]
    assert _physical_ids(cfn, ref["stack"])["Application"] == first, (
        f"the application's physical id must be its name {first!r}"
    )
    assert _outputs(stack) == {"ApplicationName": first}, f"Ref output {_outputs(stack)!r}"
    first_arn = f"arn:{partition}:elasticbeanstalk:{ctx.region}:{ctx.account}:application/{first}"
    _assert_application(ctx, eb, first, first_arn, "first description", [])
    _add_template(eb, first, template_name, solution_stack)
    _assert_application(ctx, eb, first, first_arn, "first description", [template_name])
    _assert_template(eb, first, template_name, solution_stack)

    # ---- 2. in-place: a new Description, the same application
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"], TemplateBody=_template(first, "second description"), Tags=_TAGS
    )
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Application"] == first, (
        "an in-place update keeps the application"
    )
    _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "Application"), first, "Application")
    _assert_application(ctx, eb, first, first_arn, "second description", [template_name])

    # ---- 3. replacement under UpdateReplacePolicy Retain: a new application, the old one kept
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"], TemplateBody=_template(second, "second description"), Tags=_TAGS
    )
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Application"] == second, (
        f"the replacement's physical id must be its name {second!r}"
    )
    _assert_replaced_and_retained(
        _rows(_events(cfn, ref["stack"]), seen, "Application"), first, second, "Application"
    )
    assert _outputs(stack) == {"ApplicationName": second}, (
        f"Ref output after replacement {_outputs(stack)!r}"
    )
    second_arn = f"arn:{partition}:elasticbeanstalk:{ctx.region}:{ctx.account}:application/{second}"
    _assert_application(ctx, eb, second, second_arn, "second description", [])
    _add_template(eb, second, template_name, solution_stack)
    _assert_template(eb, second, template_name, solution_stack)
    _assert_application(ctx, eb, first, first_arn, "second description", [template_name])
    _assert_template(eb, first, template_name, solution_stack)

    # ---- 4. delete: the stack's application and its template are gone; the retained one stays
    _delete_stack(ctx, cfn, ref["stack"])
    got = _wait_error(
        ctx,
        lambda: eb.describe_configuration_settings(
            ApplicationName=second, TemplateName=template_name
        ),
        _not_found(second)[0],
        f"application {second}",
    )
    assert got == _not_found(second), f"DescribeConfigurationSettings after delete: {got!r}"
    gone = eb.describe_applications(ApplicationNames=[second])["Applications"]
    assert gone == [], f"DescribeApplications still lists the deleted application: {gone!r}"
    _assert_application(ctx, eb, first, first_arn, "second description", [template_name])


def _solution_stack(eb) -> str:
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    picked = [s for s in stacks if "running Python" in s]
    assert picked, f"no Python solution stack among {len(stacks)} stacks"
    return picked[0]


def _add_template(eb, app_name: str, template_name: str, solution_stack: str) -> None:
    """The application takes a configuration template created through its own API."""
    created = eb.create_configuration_template(
        ApplicationName=app_name,
        TemplateName=template_name,
        SolutionStackName=solution_stack,
        OptionSettings=[{"Namespace": _OPTION[0], "OptionName": _OPTION[1], "Value": _OPTION[2]}],
    )
    got = (created["ApplicationName"], created["TemplateName"], created["SolutionStackName"])
    assert got == (app_name, template_name, solution_stack), (
        f"CreateConfigurationTemplate answered {got!r}"
    )


def _assert_template(eb, app_name: str, template_name: str, solution_stack: str) -> None:
    settings = eb.describe_configuration_settings(
        ApplicationName=app_name, TemplateName=template_name
    )["ConfigurationSettings"]
    got = [
        (
            s["ApplicationName"],
            s["TemplateName"],
            s["SolutionStackName"],
            {(o["Namespace"], o["OptionName"]): o.get("Value") for o in s["OptionSettings"]}.get(
                _OPTION[:2]
            ),
        )
        for s in settings
    ]
    want = [(app_name, template_name, solution_stack, _OPTION[2])]
    assert got == want, f"DescribeConfigurationSettings {got!r}, expected {want!r}"


def _assert_application(ctx, eb, name: str, arn: str, description: str, templates: list[str]):
    """DescribeApplications lists exactly the application, as templated, with *templates*.

    The read is polled: an update can take a moment to reach every read.
    """
    want = [(name, arn, description, templates)]
    timeout = _budget_s(ctx, _PROPAGATE_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        got = [
            (
                a["ApplicationName"],
                a.get("ApplicationArn"),
                a.get("Description"),
                sorted(a.get("ConfigurationTemplates", [])),
            )
            for a in eb.describe_applications(ApplicationNames=[name])["Applications"]
        ]
        if got == want:
            return
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended before {name} read {want!r}")
            raise AssertionError(f"DescribeApplications {got!r}, expected {want!r}")
        time.sleep(_POLL_S)


def _delete_application(eb, name: str) -> None:
    try:
        eb.delete_application(ApplicationName=name, TerminateEnvByForce=False)
    except ClientError as exc:
        if (exc.response["Error"].get("Code"), exc.response["Error"].get("Message")) != (
            _not_found(name)
        ):
            raise


# ===== helpers =====


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s.

    The wait then fails with its own message. With ctx None (teardown) it is cap_s.
    """
    left = None if ctx is None else ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = None if ctx is None else ctx.time_left()
    return left is not None and left <= 6.0


def _settle(ctx, cfn, stack_id: str) -> dict:
    """Poll DescribeStacks by StackId until the stack leaves every *_IN_PROGRESS status."""
    timeout = _budget_s(ctx, _STACK_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {stack_id} was {stack['StackStatus']}")
            raise AssertionError(
                f"stack {stack_id} still {stack['StackStatus']!r} after {timeout:.0f}s"
            )
        time.sleep(_POLL_S)


def _expect(cfn, stack: dict, want: str) -> None:
    """The settled stack is in status *want*; otherwise name every failed resource event."""
    if stack["StackStatus"] == want:
        return
    failed = [
        (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
        for e in _events(cfn, stack["StackId"])
        if e["ResourceStatus"].endswith("_FAILED")
    ]
    raise AssertionError(
        f"stack ended {stack['StackStatus']!r} ({stack.get('StackStatusReason')!r}), expected "
        f"{want!r}; failed events: {failed!r}"
    )


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first."""
    events: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return list(reversed(events))


def _rows(events: list[dict], seen: set[str], logical_id: str) -> list[tuple]:
    """(status, reason, physical id) of *logical_id*'s events not in *seen*, oldest first."""
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in events
        if e["EventId"] not in seen and e["LogicalResourceId"] == logical_id
    ]


def _assert_in_place(rows: list[tuple], physical_id: str, logical_id: str) -> None:
    """The resource's update events are exactly an in-place update ending on *physical_id*."""
    statuses = [status for status, _, _ in rows]
    assert statuses == ["UPDATE_IN_PROGRESS", "UPDATE_COMPLETE"], (
        f"{logical_id} must update in place with no replacement, its events were {rows!r}"
    )
    assert rows[-1][2] == physical_id, (
        f"{logical_id} must complete its update on {physical_id!r}, its events were {rows!r}"
    )


def _assert_replaced_and_retained(rows: list[tuple], old_id: str, new_id: str, logical_id: str):
    """The resource's events replace *old_id* with *new_id* and skip deleting *old_id*."""
    statuses = [(status, reason) for status, reason, _ in rows]
    assert (
        "UPDATE_IN_PROGRESS",
        "Requested update requires the creation of a new physical resource; hence creating one.",
    ) in statuses, f"{logical_id} must announce its replacement, its events were {rows!r}"
    assert ("UPDATE_COMPLETE", new_id) in [(s, pid) for s, _, pid in rows], (
        f"{logical_id} must complete as the new physical id {new_id!r}, its events were {rows!r}"
    )
    old_rows = [(status, pid) for status, _, pid in rows if status.startswith("DELETE_")]
    assert old_rows == [("DELETE_SKIPPED", old_id)], (
        f"UpdateReplacePolicy Retain must skip deleting the replaced {old_id!r}, the delete events "
        f"of {logical_id} were {old_rows!r}"
    )


def _physical_ids(cfn, stack_id: str) -> dict[str, str]:
    """Logical id -> physical id of every resource in the stack."""
    return {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    }


def _outputs(stack: dict) -> dict[str, str]:
    return {o["OutputKey"]: o.get("OutputValue") for o in stack.get("Outputs", [])}


def _wait_error(ctx, fn, code: str, what: str):
    """Poll ``fn`` until it raises *code* (a delete can lag DELETE_COMPLETE); (code, message)."""
    timeout = _budget_s(ctx, _GONE_CAP_S)
    deadline = time.monotonic() + timeout
    last = "never read"
    while True:
        try:
            last = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == code:
                return err.get("Code"), err.get("Message")
            raise
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {what} still answered")
            raise AssertionError(f"{what} still answered after {timeout:.0f}s: {last!r}")
        time.sleep(_POLL_S)


def _delete_stack(ctx, cfn, stack_id: str) -> None:
    """Delete the stack by StackId and wait for DELETE_COMPLETE; raises on any other end."""
    cfn.delete_stack(StackName=stack_id)
    _expect(cfn, _settle(ctx, cfn, stack_id), "DELETE_COMPLETE")


def _teardown_stack(ctx, cfn, ref: dict) -> None:
    """Teardown by the StackId once known, else by name; a stack that never existed is done."""
    try:
        stack = cfn.describe_stacks(StackName=ref["stack"])["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"]["Message"] == f"Stack with id {ref['stack']} does not exist":
            return
        raise
    if stack["StackStatus"] == "DELETE_COMPLETE":
        return
    if stack["StackStatus"].endswith("_IN_PROGRESS"):
        stack = _settle(ctx, cfn, stack["StackId"])
    _delete_stack(ctx, cfn, stack["StackId"])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
