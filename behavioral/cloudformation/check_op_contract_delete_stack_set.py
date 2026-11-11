"""op-contract-deleteStackSet."""

from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteStackSet"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]

_TEMPLATE = json.dumps({"Resources": {"Topic": {"Type": "AWS::SNS::Topic"}}})


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """DeleteStackSet removes an empty stack set (later Describe/Update fail with
    StackSetNotFoundException) and, being idempotent, succeeds silently for an unknown name."""
    cfn = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-cfn-ss-")

    resp = cfn.create_stack_set(
        StackSetName=name,
        TemplateBody=_TEMPLATE,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    stack_set_id = resp["StackSetId"]
    # DeleteStackSet is idempotent, so this teardown is a no-op once the check deletes the set itself.
    ctx.on_cleanup(lambda: cfn.delete_stack_set(StackSetName=name))

    described = cfn.describe_stack_set(StackSetName=name)["StackSet"]
    assert described["StackSetId"] == stack_set_id, (
        f"expected StackSetId {stack_set_id}, got {described['StackSetId']}"
    )
    assert described["Status"] == "ACTIVE", (
        f"expected Status ACTIVE, got {described['Status']}"
    )

    cfn.delete_stack_set(StackSetName=name)

    code, message = _error(lambda: cfn.describe_stack_set(StackSetName=name))
    assert code == "StackSetNotFoundException", (
        f"expected StackSetNotFoundException after delete, got {code}"
    )
    assert message == f"StackSet {name} not found", (
        f"unexpected StackSetNotFoundException message {message!r}"
    )

    # The deleted stack set must also be unusable, not merely unreadable: a
    # mutation against the same dead id is rejected with the identical code.
    update_code, update_message = _error(
        lambda: cfn.update_stack_set(StackSetName=name, UsePreviousTemplate=True)
    )
    assert update_code == "StackSetNotFoundException", (
        f"expected StackSetNotFoundException on UpdateStackSet of a deleted stack set, got {update_code}"
    )
    assert update_message == f"StackSet {name} not found", (
        f"unexpected StackSetNotFoundException message {update_message!r}"
    )

    # Idempotency boundary: delete a stack set name that was never created.
    # DeleteStackSet mirrors DeleteStack semantics and does not error when
    # the target does not exist.
    bogus = ctx.unique_name("sim2real-cfn-ss-missing-")
    try:
        cfn.delete_stack_set(StackSetName=bogus)
    except ClientError as exc:
        raise AssertionError(
            f"expected DeleteStackSet on unknown name to succeed silently, got {exc.response['Error']}"
        ) from exc




def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
