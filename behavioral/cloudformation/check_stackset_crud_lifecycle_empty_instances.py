"""stackset-crud-lifecycle-empty-instances."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stackset-crud-lifecycle-empty-instances"
GROUP = 'stack_sets'
SERVICES = ['cloudformation']


def _client_error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    success raises, so a target that accepts a call AWS refuses fails as an acceptance rather
    than as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

def _expect_error(fn, expected):
    """Assert fn() raises a ClientError whose (code, message) is exactly *expected*."""
    got = _client_error(fn)
    assert got == expected, f"expected {expected!r}, got {got!r}"

def _wait_stackset_operation(cf, ss_name, op_id, targets, timeout_s=240):
    deadline = time.monotonic() + timeout_s
    op = None
    while time.monotonic() < deadline:
        op = cf.describe_stack_set_operation(StackSetName=ss_name, OperationId=op_id)[
            "StackSetOperation"
        ]
        if op.get("Status") in targets:
            return op
        time.sleep(5)
    return op

def _sns_template(tags=None):
    props = {}
    if tags:
        props["Tags"] = [{"Key": k, "Value": v} for k, v in tags.items()]
    return json.dumps(
        {
            "Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": props}},
            "Outputs": {"TopicArn": {"Value": {"Ref": "Topic"}}},
        }
    )

def _phase_tag(template_body):
    """Pull the Topic's 'phase' tag value back out of a StackSet's persisted
    TemplateBody, tolerating whatever whitespace/ordering CFN echoes it back with."""
    props = json.loads(template_body)["Resources"]["Topic"]["Properties"]
    for t in props.get("Tags", []):
        if t["Key"] == "phase":
            return t["Value"]
    return None


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Create/Update/DeleteStackSet with zero instances records StackSet operations, persists
    the new TemplateBody (read back via DescribeStackSet), and once deleted the stack set leaves
    ListStackSets and refuses a read and a further mutation by name."""
    cf = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-behav-stackset-crud-")
    created = cf.create_stack_set(StackSetName=name, TemplateBody=_sns_template(tags={"phase": "1"}))
    stack_set_id = created["StackSetId"]
    ctx.on_cleanup(lambda: cf.delete_stack_set(StackSetName=name))

    desc = cf.describe_stack_set(StackSetName=name)["StackSet"]
    assert desc["StackSetId"] == stack_set_id, desc
    assert desc["Status"] == "ACTIVE", desc
    assert _phase_tag(desc["TemplateBody"]) == "1", desc["TemplateBody"]

    listed = cf.list_stack_sets(Status="ACTIVE")["Summaries"]
    assert any(s["StackSetName"] == name for s in listed), listed

    update_resp = cf.update_stack_set(StackSetName=name, TemplateBody=_sns_template(tags={"phase": "2"}))
    op_id = update_resp["OperationId"]
    op = _wait_stackset_operation(cf, name, op_id, {"SUCCEEDED", "FAILED", "STOPPED"})
    assert op["Status"] == "SUCCEEDED", op

    ops = cf.list_stack_set_operations(StackSetName=name)["Summaries"]
    assert any(o["OperationId"] == op_id for o in ops), ops

    updated_template = cf.get_template_summary(StackSetName=name)
    assert "AWS::SNS::Topic" in updated_template["ResourceTypes"], updated_template

    # get_template_summary's ResourceTypes is unchanged by the update (still just
    # SNS::Topic) — the independent read that actually proves UpdateStackSet
    # persisted the NEW body is describe_stack_set's own TemplateBody.
    desc_after_update = cf.describe_stack_set(StackSetName=name)["StackSet"]
    assert _phase_tag(desc_after_update["TemplateBody"]) == "2", desc_after_update["TemplateBody"]

    cf.delete_stack_set(StackSetName=name)

    _expect_error(
        lambda: cf.describe_stack_set(StackSetName=name),
        ("StackSetNotFoundException", f"StackSet {name} not found"),
    )
    listed_after = cf.list_stack_sets(Status="ACTIVE")["Summaries"]
    assert not any(s["StackSetName"] == name for s in listed_after), listed_after

    _expect_error(
        lambda: cf.update_stack_set(StackSetName=name, TemplateBody=_sns_template()),
        ("StackSetNotFoundException", f"StackSet {name} not found"),
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
