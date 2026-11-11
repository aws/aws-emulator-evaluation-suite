"""deploy-appstream-fleet-stack-association-round-trip-and-delete."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-appstream-fleet-stack-association-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["appstream", "cloudformation"]

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

_INSTANCE_TYPE = "stream.standard.small"
_TAG_KEY = "sim2real-asfleet"
#: AppStream's dated public Windows Server 2019 base images for standard instance types; the
#: graphics images carry a family infix and do not match.
_BASE_IMAGE_RE = re.compile(r"^AppStream-WinServer2019-\d{2}-\d{2}-\d{4}$")


def _base_image(appstream):
    """The newest AVAILABLE public non-graphics Windows Server 2019 base image's name.

    AppStream retires dated public images, so the name is read from DescribeImages on each run.
    """
    images = [i for i in paginate(appstream, "describe_images", "Images", Type="PUBLIC")
              if _BASE_IMAGE_RE.match(i["Name"]) and i.get("Platform") == "WINDOWS_SERVER_2019"
              and i.get("State") == "AVAILABLE"]
    assert images, "DescribeImages(Type=PUBLIC) lists no AVAILABLE Windows Server 2019 base image"
    return max(images, key=lambda i: i.get("PublicBaseImageReleasedDate") or i["CreatedTime"])[
        "Name"]


def _template(fleet_name, stack_name, tag_value, image_name, with_association=True):
    tags_block = [{"Key": _TAG_KEY, "Value": tag_value}]
    resources = {
        "Fleet": {
            "Type": "AWS::AppStream::Fleet",
            "Properties": {
                "Name": fleet_name,
                "InstanceType": _INSTANCE_TYPE,
                "ImageName": image_name,
                "ComputeCapacity": {"DesiredInstances": 1},
                "FleetType": "ON_DEMAND",
                "Tags": tags_block,
            },
        },
        "Stack": {
            "Type": "AWS::AppStream::Stack",
            "Properties": {"Name": stack_name, "Tags": tags_block},
        },
    }
    outputs = {
        "FleetRef": {"Value": {"Ref": "Fleet"}},
        "FleetArn": {"Value": {"Fn::GetAtt": ["Fleet", "Arn"]}},
        "StackRef": {"Value": {"Ref": "Stack"}},
    }
    if with_association:
        resources["Association"] = {
            "Type": "AWS::AppStream::StackFleetAssociation",
            "Properties": {"FleetName": {"Ref": "Fleet"}, "StackName": {"Ref": "Stack"}},
        }
        outputs["AssociationRef"] = {"Value": {"Ref": "Association"}}
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources,
                       "Outputs": outputs})


def _own_tags(appstream, arn):
    """The resource's tags without the ``aws:`` keys CloudFormation adds."""
    got = appstream.list_tags_for_resource(ResourceArn=arn).get("Tags", {})
    return {k: v for k, v in got.items() if not k.startswith("aws:")}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control", "requires:appstream-service-access")
def run(ctx) -> None:
    """A CloudFormation AppStream fleet, stack and their association read back through AppStream.

    Every templated property, tag, Ref and the fleet Arn match AppStream; an update dropping the
    association disassociates the same fleet, and deleting the stack removes the fleet and stack.
    """
    appstream = ctx.client("appstream")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-asdeploy-")
    fleet_name = ctx.unique_name("sim2real-asfleet-")
    as_stack_name = ctx.unique_name("sim2real-asstack-")

    image_name = _base_image(appstream)
    stack_id = create_stack(ctx, cfn, stack,
                            _template(fleet_name, as_stack_name, stack, image_name))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    partition = stack_id.split(":")[1]
    fleet_arn = f"arn:{partition}:appstream:{ctx.region}:{ctx.account}:fleet/{fleet_name}"
    stack_arn = f"arn:{partition}:appstream:{ctx.region}:{ctx.account}:stack/{as_stack_name}"

    # Refs against independent reads: the full fleet and stack listings, by the declared names.
    fleets = [f for f in paginate(appstream, "describe_fleets", "Fleets")
              if f["Name"] == fleet_name]
    assert [f["Name"] for f in fleets] == [out["FleetRef"]] == [fleet_name], (
        f"DescribeFleets lists {[f['Name'] for f in fleets]!r} for Ref {out['FleetRef']!r}"
    )
    fleet = fleets[0]
    # The read-only GetAtt Arn == the service value == the documented format.
    assert (out["FleetArn"], fleet["Arn"]) == (fleet_arn, fleet_arn), (
        f"GetAtt Arn {out['FleetArn']!r}, DescribeFleets Arn {fleet['Arn']!r}, want {fleet_arn!r}"
    )
    got = (fleet["InstanceType"], fleet["ImageName"], fleet["FleetType"],
           fleet["ComputeCapacityStatus"]["Desired"], fleet["State"])
    want = (_INSTANCE_TYPE, image_name, "ON_DEMAND", 1, "STOPPED")
    assert got == want, f"fleet reads {got!r}, expected {want!r}"
    fleet_tags = _own_tags(appstream, fleet_arn)
    assert fleet_tags == {"sim2real": stack, _TAG_KEY: stack}, f"fleet tags {fleet_tags!r}"

    stacks = [s for s in paginate(appstream, "describe_stacks", "Stacks")
              if s["Name"] == as_stack_name]
    assert [s["Name"] for s in stacks] == [out["StackRef"]] == [as_stack_name], (
        f"DescribeStacks lists {[s['Name'] for s in stacks]!r} for Ref {out['StackRef']!r}"
    )
    assert stacks[0]["Arn"] == stack_arn, f"stack Arn {stacks[0]['Arn']!r}, want {stack_arn!r}"
    stack_tags = _own_tags(appstream, stack_arn)
    assert stack_tags == {"sim2real": stack, _TAG_KEY: stack}, f"stack tags {stack_tags!r}"

    # The association's Ref is its compound identifier; both directions list it.
    assert out["AssociationRef"] == f"{fleet_name}|{as_stack_name}", (
        f"StackFleetAssociation Ref {out['AssociationRef']!r}"
    )
    got = (paginate(appstream, "list_associated_stacks", "Names", FleetName=fleet_name),
           paginate(appstream, "list_associated_fleets", "Names", StackName=as_stack_name))
    assert got == ([as_stack_name], [fleet_name]), f"associations read {got!r}"

    # Child before parent: the update drops only the association; the same fleet (its
    # CreatedTime) and stack still answer with nothing associated.
    cfn.update_stack(StackName=stack_id,
                     TemplateBody=_template(fleet_name, as_stack_name, stack, image_name,
                                            with_association=False))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"association-removing update ended {status!r}"
    after = appstream.describe_fleets(Names=[fleet_name])["Fleets"]
    assert [f["CreatedTime"] for f in after] == [fleet["CreatedTime"]], (
        f"fleet after the update reads {after!r}"
    )
    got = (paginate(appstream, "list_associated_stacks", "Names", FleetName=fleet_name),
           paginate(appstream, "list_associated_fleets", "Names", StackName=as_stack_name))
    assert got == ([], []), f"associations after dropping StackFleetAssociation: {got!r}"

    fleet_gone = ("ResourceNotFoundException",
                  f"The fleet {fleet_name} for account {ctx.account} does not exist.")
    stack_gone = ("ResourceNotFoundException",
                  f"The stack {as_stack_name} for account {ctx.account} does not exist.")
    delete_stack(cfn, stack_id)
    until_raises(lambda: appstream.describe_fleets(Names=[fleet_name]))
    expect_error(lambda: appstream.describe_fleets(Names=[fleet_name]), *fleet_gone)
    until_raises(lambda: appstream.describe_stacks(Names=[as_stack_name]))
    expect_error(lambda: appstream.describe_stacks(Names=[as_stack_name]), *stack_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
