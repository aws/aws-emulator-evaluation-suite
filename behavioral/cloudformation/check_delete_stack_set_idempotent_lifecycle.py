"""delete-stack-set-idempotent-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-stack-set-idempotent-lifecycle"
GROUP = "stack_sets"
SERVICES = ["cloudformation"]

_TEMPLATE = '{"Resources":{"Topic":{"Type":"AWS::SNS::Topic"}}}'


def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """DeleteStackSet on an empty stack set is idempotent: a repeat delete still succeeds,
    ListStackSets(DELETED) keeps the old id, the freed name recreates under a new
    StackSetId, and a never-created name also deletes cleanly."""
    cfn = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-behav-ssidem-")

    first = cfn.create_stack_set(
        StackSetName=name,
        TemplateBody=_TEMPLATE,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    first_id = first["StackSetId"]
    ctx.on_cleanup(lambda: cfn.delete_stack_set(StackSetName=name))

    cfn.delete_stack_set(StackSetName=name)

    not_found = ("StackSetNotFoundException", f"StackSet {name} not found")
    got = _error(lambda: cfn.describe_stack_set(StackSetName=name))
    assert got == not_found, f"describe after first delete: expected {not_found!r}, got {got!r}"

    second_delete = cfn.delete_stack_set(StackSetName=name)
    assert second_delete["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected a repeat DeleteStackSet on the same deleted name to return 200, got "
        f"{second_delete['ResponseMetadata']['HTTPStatusCode']!r}"
    )

    deleted_sets = [
        s
        for page in cfn.get_paginator("list_stack_sets").paginate(Status="DELETED")
        for s in page["Summaries"]
    ]
    deleted_ids = {s["StackSetId"] for s in deleted_sets if s["StackSetName"] == name}
    assert deleted_ids == {first_id}, (
        f"expected ListStackSets(DELETED) to list only {first_id!r} for {name!r}, got "
        f"{deleted_ids!r}"
    )

    second = cfn.create_stack_set(
        StackSetName=name,
        TemplateBody=_TEMPLATE,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    second_id = second["StackSetId"]
    ctx.on_cleanup(lambda: cfn.delete_stack_set(StackSetName=name))
    assert second_id != first_id, (
        f"expected a fresh StackSetId on reuse of the freed name {name!r}, got the same id "
        f"{first_id!r}"
    )

    described = cfn.describe_stack_set(StackSetName=name)["StackSet"]
    assert described["StackSetId"] == second_id, (
        f"expected DescribeStackSet to report the new id {second_id!r}, got "
        f"{described['StackSetId']!r}"
    )
    assert described["Status"] == "ACTIVE", (
        f"expected the recreated stack set to be ACTIVE, got {described['Status']!r}"
    )

    bogus = ctx.unique_name("sim2real-behav-ssidem-missing-")
    bogus_delete = cfn.delete_stack_set(StackSetName=bogus)
    assert bogus_delete["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected DeleteStackSet on a never-created name to return 200, got "
        f"{bogus_delete['ResponseMetadata']['HTTPStatusCode']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
