"""deploy-translate-terminology-round-trip-and-delete."""
from __future__ import annotations

import base64
import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-translate-terminology-round-trip-and-delete"
GROUP = "cloudformation"
SERVICES = ["cloudformation", "translate"]

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


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


# ---- Check-specific: the template, then run(). ----

_CSV = "en,es\nconference room,sala de reuniones\n"
_DESCRIPTION = "sim2real terminology round trip"


def _template(name: str) -> str:
    file_b64 = base64.b64encode(_CSV.encode()).decode()
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Term": {
                "Type": "AWS::Translate::Terminology",
                "Properties": {
                    "Name": name,
                    "Description": _DESCRIPTION,
                    "TerminologyData": {"File": file_b64, "Format": "CSV"},
                    "Tags": [{"Key": "sim2real-term", "Value": name}],
                },
            }
        },
        "Outputs": {
            "TermArn": {"Value": {"Ref": "Term"}},
            "SourceLanguageCode": {"Value": {"Fn::GetAtt": "Term.SourceLanguageCode"}},
            "TargetLanguageCodes": {
                "Value": {"Fn::Join": [",", {"Fn::GetAtt": "Term.TargetLanguageCodes"}]}
            },
            "Format": {"Value": {"Fn::GetAtt": "Term.Format"}},
        },
    })


def _error(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) the call raises; an unexpected success fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::Translate::Terminology imports its inline CSV, and Translate shows the
    Ref ARN it lists for the name, the declared properties and tags and the derived read-only
    attributes; deleting the stack removes it from GetTerminology.
    """
    translate = ctx.client("translate")
    cfn = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-term-")
    stack = ctx.unique_name("sim2real-termstack-")

    stack_id = create_stack(ctx, cfn, stack, _template(name))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)

    listed = [t["Arn"] for t in paginate(translate, "list_terminologies",
                                         "TerminologyPropertiesList") if t["Name"] == name]
    assert listed == [outputs["TermArn"]], f"ListTerminologies {listed!r} for Ref {outputs['TermArn']!r}"
    got = translate.get_terminology(Name=name, TerminologyDataFormat="CSV")["TerminologyProperties"]
    read = {k: got.get(k) for k in ("Arn", "SourceLanguageCode", "TargetLanguageCodes", "Format",
                                    "TermCount", "Description")}
    want = {"Arn": outputs["TermArn"], "SourceLanguageCode": "en", "TargetLanguageCodes": ["es"],
            "Format": "CSV", "TermCount": 1, "Description": _DESCRIPTION}
    assert read == want, f"GetTerminology {read!r}, expected {want!r}"
    getatts = (outputs["SourceLanguageCode"], outputs["TargetLanguageCodes"], outputs["Format"])
    assert getatts == ("en", "es", "CSV"), f"GetAtt (source, targets, format) {getatts!r}"
    tags_ = {t["Key"]: t["Value"] for t in
             translate.list_tags_for_resource(ResourceArn=got["Arn"]).get("Tags", [])
             if not t["Key"].startswith("aws:")}
    assert tags_ == {"sim2real": stack, "sim2real-term": name}, f"terminology tags {tags_!r}"

    delete_stack(cfn, stack_id)
    code, message = _error(lambda: translate.get_terminology(Name=name))
    got = (code, masked(message or "", ctx.account, name))
    assert got == ("ResourceNotFoundException", "The Terminology for <account> <name> was not found"), (
        f"reading the deleted terminology gave {got!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
