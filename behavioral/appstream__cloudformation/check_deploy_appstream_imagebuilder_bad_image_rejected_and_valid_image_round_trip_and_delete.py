"""deploy-appstream-imagebuilder-bad-image-rejected-and-valid-image-round-trip-and-delete."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-appstream-imagebuilder-bad-image-rejected-and-valid-image-round-trip-and-delete"
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


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


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

_INSTANCE_TYPE = "stream.standard.small"
_TAG_KEY = "sim2real-asib"
#: An image builder can take about ten minutes to reach RUNNING.
_BUILDER_WAIT_S = 900.0
_REJECTED = (
    "Resource of type 'AWS::AppStream::ImageBuilder' with identifier '<name>' was not found.",
    "NotFound",
)
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


def _template(builder_name, image_name, tag_value):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Builder": {
                "Type": "AWS::AppStream::ImageBuilder",
                "Properties": {
                    "Name": builder_name,
                    "InstanceType": _INSTANCE_TYPE,
                    "ImageName": image_name,
                    "Tags": [{"Key": _TAG_KEY, "Value": tag_value}],
                },
            },
        },
        "Outputs": {"BuilderRef": {"Value": {"Ref": "Builder"}}},
    })


def _listed(appstream, name):
    """The image builders named ``name`` in the full DescribeImageBuilders listing."""
    return [b for b in paginate(appstream, "describe_image_builders", "ImageBuilders")
            if b["Name"] == name]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "concern:representation", "plane:control", "requires:appstream-service-access")
def run(ctx) -> None:
    """A CloudFormation AppStream image builder naming a nonexistent image fails and rolls back.

    The handler's NotFound reason is graded and AppStream lists no such builder, while the same
    template with a real image reads back through AppStream and its stack delete removes it.
    """
    appstream = ctx.client("appstream")
    cfn = ctx.client("cloudformation")
    good_stack = ctx.unique_name("sim2real-asib-goodstack-")
    bad_stack = ctx.unique_name("sim2real-asib-badstack-")
    good_builder = ctx.unique_name("sim2real-asib-good-")
    bad_builder = ctx.unique_name("sim2real-asib-bad-")
    bad_image = ctx.unique_name("sim2real-asib-noimage-")

    image_name = _base_image(appstream)
    builder_gone = ("ResourceNotFoundException",
                    f"The image builder {bad_builder} for account {ctx.account} does not exist.")
    good_gone = ("ResourceNotFoundException",
                 f"The image builder {good_builder} for account {ctx.account} does not exist.")

    # Both stacks start at once: the control's builder is the slow part.
    good_id = create_stack(ctx, cfn, good_stack, _template(good_builder, image_name, good_stack))
    bad_id = create_stack(ctx, cfn, bad_stack, _template(bad_builder, bad_image, bad_stack))

    status = wait_stack(cfn, bad_id, timeout_s=_BUILDER_WAIT_S)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    rows = validation_rows(cfn, bad_id)
    assert rows == [], f"refused by early validation, not by the handler: {rows!r}"
    reason = failed_reason(stack_events(cfn, bad_id), "Builder")
    got = handler_reason(reason, ctx.account, bad_builder, bad_image)
    assert got == _REJECTED, f"handler reason {got!r}, expected {_REJECTED!r}"

    # Rollback absence through AppStream, by the name the builder would have, BEFORE any delete.
    listed = _listed(appstream, bad_builder)
    assert listed == [], f"the rolled-back image builder is listed: {listed!r}"
    expect_error(lambda: appstream.describe_image_builders(Names=[bad_builder]), *builder_gone)

    # Positive control: the same template with a real image (the one property made valid).
    status = wait_stack(cfn, good_id, timeout_s=_BUILDER_WAIT_S)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cfn, good_id))!r}"
    )
    out = stack_outputs(cfn, good_id)
    partition = good_id.split(":")[1]
    builders = _listed(appstream, good_builder)
    assert [b["Name"] for b in builders] == [out["BuilderRef"]] == [good_builder], (
        f"DescribeImageBuilders lists {[b['Name'] for b in builders]!r} "
        f"for Ref {out['BuilderRef']!r}"
    )
    builder = builders[0]
    image_arn = f"arn:{partition}:appstream:{ctx.region}::image/{image_name}"
    builder_arn = (
        f"arn:{partition}:appstream:{ctx.region}:{ctx.account}:image-builder/{good_builder}"
    )
    got = (builder["Arn"], builder["InstanceType"], builder["ImageArn"], builder["State"])
    want = (builder_arn, _INSTANCE_TYPE, image_arn, "RUNNING")
    assert got == want, f"image builder reads {got!r}, expected {want!r}"
    tags_read = appstream.list_tags_for_resource(ResourceArn=builder_arn).get("Tags", {})
    own = {k: v for k, v in tags_read.items() if not k.startswith("aws:")}
    assert own == {"sim2real": good_stack, _TAG_KEY: good_stack}, f"builder tags {own!r}"

    delete_stack(cfn, good_id)
    until_raises(lambda: appstream.describe_image_builders(Names=[good_builder]))
    expect_error(lambda: appstream.describe_image_builders(Names=[good_builder]), *good_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
