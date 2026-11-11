"""deploy-bedrock-agent-runtime-session-nonexistent-kms-key-rejected-and-rolled-back."""
from __future__ import annotations

import datetime
import json
import re
import time

from behavioral_harness import tags

CHECK = "deploy-bedrock-agent-runtime-session-nonexistent-kms-key-rejected-and-rolled-back"
GROUP = "deploy"
SERVICES = ["bedrock-agent-runtime", "cloudformation"]

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


# ---- Check-specific: the template, then run(). ----

_METADATA_KEY = "purpose"

_REJECTED = (
    "Check that your IAM role has the necessary KMS permissions in both the key policy and IAM "
    "policy, then retry your request. (Service: Bedrock Agent Runtime; Operation: CreateSession; "
    "Status Code: 403; Error Code: AccessDeniedException; Request ID: <id>)",
    "AccessDenied",
)


def _template(encryption_key_arn, metadata_value: str) -> str:
    """A check-owned KMS key and a Session; only the Session's EncryptionKeyArn varies."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Key": {
                "Type": "AWS::KMS::Key",
                "Properties": {
                    "PendingWindowInDays": 7,
                    "KeyPolicy": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"AWS": {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"}},
                            "Action": "kms:*",
                            "Resource": "*",
                        }],
                    },
                },
            },
            "Session": {
                "Type": "AWS::Bedrock::Session",
                "Properties": {
                    "EncryptionKeyArn": encryption_key_arn,
                    "SessionMetadata": {_METADATA_KEY: metadata_value},
                },
            },
        },
        "Outputs": {
            "SessionArn": {"Value": {"Ref": "Session"}},
            "KeyArn": {"Value": {"Fn::GetAtt": ["Key", "Arn"]}},
        },
    })


def _sessions_carrying(bar, metadata_value: str, since: datetime.datetime) -> list[str]:
    """Arns of sessions created at or after ``since`` whose metadata holds ``metadata_value``."""
    found: list[str] = []
    for summary in paginate(bar, "list_sessions", "sessionSummaries"):
        if summary["createdAt"] < since:
            continue
        session = bar.get_session(sessionIdentifier=summary["sessionArn"])
        if session.get("sessionMetadata", {}).get(_METADATA_KEY) == metadata_value:
            found.append(summary["sessionArn"])
    return found


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """A Session whose EncryptionKeyArn names a KMS key that does not exist is refused, the stack
    rolls back and no session carries its metadata; the same template naming the stack's own key
    deploys a session that reads back with that key and metadata.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-bedrock-session.html
    """
    bar = ctx.client("bedrock-agent-runtime")
    cf = ctx.client("cloudformation")
    bad_stack = ctx.unique_name("sim2real-sessionbad-")
    bad_metadata = ctx.unique_name("sim2real-sessionbad-meta-")
    missing_key_arn = f"arn:{cf.meta.partition}:kms:{ctx.region}:{ctx.account}:key/00000000-0000-0000-0000-000000000000"
    started = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=1)

    bad_id = create_stack(ctx, cf, bad_stack, _template(missing_key_arn, bad_metadata))
    status = wait_stack(cf, bad_id)
    assert status == "ROLLBACK_COMPLETE", (
        f"stack {bad_stack!r} ended {status!r}, expected ROLLBACK_COMPLETE"
    )

    reason = failed_reason(stack_events(cf, bad_id), "Session")
    got = handler_reason(reason, ctx.account, bad_stack, bad_metadata)
    assert got == _REJECTED, f"expected the handler reason {_REJECTED!r}, got {got!r}"

    resources = cf.describe_stack_resources(StackName=bad_id)["StackResources"]
    session_rows = [r for r in resources if r["LogicalResourceId"] == "Session"]
    assert len(session_rows) == 1 and session_rows[0].get("PhysicalResourceId") in (None, ""), (
        f"expected the rejected Session to carry no PhysicalResourceId, got {session_rows!r}"
    )
    carrying = _sessions_carrying(bar, bad_metadata, started)
    assert carrying == [], f"expected no session to carry the rejected metadata, found {len(carrying)}"

    delete_stack(cf, bad_id)

    # Positive control: the same template, the Session naming the stack's own key.
    good_stack = ctx.unique_name("sim2real-sessiongood-")
    good_metadata = ctx.unique_name("sim2real-sessiongood-meta-")
    good_id = create_stack(ctx, cf, good_stack,
                           _template({"Fn::GetAtt": ["Key", "Arn"]}, good_metadata))
    good_status = wait_stack(cf, good_id)
    assert good_status == "CREATE_COMPLETE", (
        f"the control stack {good_stack!r} ended {good_status!r}, expected CREATE_COMPLETE"
    )
    outputs = stack_outputs(cf, good_id)
    control = bar.get_session(sessionIdentifier=outputs["SessionArn"])
    assert control["sessionArn"] == outputs["SessionArn"], (
        f"expected the control session's arn to equal the stack's Ref, got {control['sessionArn']!r}"
    )
    assert control["sessionStatus"] == "ACTIVE", (
        f"expected the control session to be ACTIVE, bedrock-agent-runtime reports "
        f"{control['sessionStatus']!r}"
    )
    assert control.get("encryptionKeyArn") == outputs["KeyArn"], (
        f"expected the control session's encryptionKeyArn to be the stack's key, got "
        f"{control.get('encryptionKeyArn')!r}"
    )
    assert control.get("sessionMetadata") == {_METADATA_KEY: good_metadata}, (
        f"expected the control session's metadata {{{_METADATA_KEY!r}: {good_metadata!r}}}, got "
        f"{control.get('sessionMetadata')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
