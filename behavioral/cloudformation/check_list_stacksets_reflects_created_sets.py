"""list-stacksets-reflects-created-sets."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-stacksets-reflects-created-sets"
GROUP = "state-machine"
SERVICES = ["cloudformation"]


def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListStackSets(Status=ACTIVE) reflects a created StackSet and stops
    listing it there once deleted, while ListStackSets(Status=DELETED) picks
    it up instead."""
    cfn = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-behav-lss-")

    stackset_id = cfn.create_stack_set(
        StackSetName=name,
        TemplateBody='{"Resources":{"Topic":{"Type":"AWS::SNS::Topic","Properties":{}}}}',
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackSetId"]
    cleanup_done = {"value": False}

    def _cleanup():
        if not cleanup_done["value"]:
            cfn.delete_stack_set(StackSetName=name)

    ctx.on_cleanup(_cleanup)

    active_before = [
        s
        for page in cfn.get_paginator("list_stack_sets").paginate(Status="ACTIVE")
        for s in page["Summaries"]
    ]
    assert any(s["StackSetId"] == stackset_id for s in active_before), (
        "ListStackSets(ACTIVE) missing the just-created stack set"
    )
    described = cfn.describe_stack_set(StackSetName=name)["StackSet"]
    assert described["Status"] == "ACTIVE", (
        f"expected newly-created stack set to be ACTIVE, got {described['Status']!r}"
    )

    cfn.delete_stack_set(StackSetName=name)
    cleanup_done["value"] = True

    active_after = [
        s
        for page in cfn.get_paginator("list_stack_sets").paginate(Status="ACTIVE")
        for s in page["Summaries"]
    ]
    assert not any(s["StackSetId"] == stackset_id for s in active_after), (
        "deleted stack set still present in ListStackSets(ACTIVE)"
    )

    deleted = [
        s
        for page in cfn.get_paginator("list_stack_sets").paginate(Status="DELETED")
        for s in page["Summaries"]
    ]
    assert any(s["StackSetId"] == stackset_id for s in deleted), (
        "ListStackSets(DELETED) does not surface the deleted stack set"
    )

    code, message = _error(lambda: cfn.describe_stack_set(StackSetName=name))
    assert code == "StackSetNotFoundException", (
        f"expected DescribeStackSet on the deleted stack set to raise "
        f"StackSetNotFoundException, got {code!r}"
    )
    assert message == f"StackSet {name} not found", (
        f"unexpected StackSetNotFoundException message {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
