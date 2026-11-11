"""deploy-sequence-store-duplicate-name-rejected."""
from __future__ import annotations

import re
import time
import uuid

from behavioral_harness import tags

CHECK = "deploy-sequence-store-duplicate-name-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "omics"]

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

_DUPLICATE = (
    "Name must be unique. (Service: Omics, Status Code: 400, Request ID: <id>) "
    "(SDK Attempt Count: <n>)",
    "AlreadyExists",
)


def _template(name, with_output=True):
    outputs = """Outputs:
  SeqStoreId:
    Value: !Ref Sim2RealSeqStore
""" if with_output else ""
    return f"""AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Sim2RealSeqStore:
    Type: AWS::Omics::SequenceStore
    Properties:
      Name: {name}
{outputs}"""


def _store_ids_named(omics, name):
    """Ids of every sequence store named ``name``, read through every page."""
    stores = paginate(omics, "list_sequence_stores", "sequenceStores", filter={"name": name})
    return [st["id"] for st in stores if st.get("name") == name]


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::Omics::SequenceStore whose Name collides with an existing store is
    rejected (AlreadyExists, "Name must be unique."), leaving the existing store the only one of
    that name; the same template with a fresh Name deploys and reads back."""
    cf = ctx.client("cloudformation")
    omics = ctx.client("omics")
    existing_name = ctx.unique_name("sim2real-xsvc-seq-existing-")
    good_name = ctx.unique_name("sim2real-xsvc-seq-good-")

    # Cleanup first, by name: a store HealthOmics accepted is deleted even if the call raises.
    ctx.on_cleanup(lambda: [omics.delete_sequence_store(id=store_id)
                            for store_id in _store_ids_named(omics, existing_name)])
    existing_id = omics.create_sequence_store(
        name=existing_name, clientToken=str(uuid.uuid4()),
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"},
    )["id"]

    # Positive control: the same template with a Name no store holds.
    good_id = create_stack(ctx, cf, ctx.unique_name("sim2real-xsvc-stk-good-"), _template(good_name))
    status = wait_stack(cf, good_id)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cf, good_id))!r}"
    )
    ref = stack_outputs(cf, good_id)["SeqStoreId"]
    good_listed = _store_ids_named(omics, good_name)
    assert good_listed == [ref], (
        f"expected Ref {ref!r} to be the one sequence store HealthOmics lists under "
        f"{good_name!r}, got {good_listed!r}"
    )
    described = omics.get_sequence_store(id=good_listed[0])
    assert described["name"] == good_name, f"expected name {good_name!r}, got {described['name']!r}"

    bad_id = create_stack(ctx, cf, ctx.unique_name("sim2real-xsvc-stk-dup-"),
                          _template(existing_name, with_output=False))
    status = wait_stack(cf, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"expected stack to roll back, ended in {status!r}"
    got = handler_reason(failed_reason(stack_events(cf, bad_id), "Sim2RealSeqStore"),
                         ctx.account, existing_name)
    assert got == _DUPLICATE, f"handler reason {got!r}, expected {_DUPLICATE!r}"

    # Before any delete: the rejected create left the existing store the only one of its name.
    named = _store_ids_named(omics, existing_name)
    assert named == [existing_id], (
        f"expected only the existing store under {existing_name!r} after the rejected create, "
        f"HealthOmics lists {named!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
