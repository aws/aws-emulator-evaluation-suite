"""stack-instance-and-refactor-not-found."""
from __future__ import annotations

import json
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-instance-and-refactor-not-found"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeStackInstance on an existing stack set that has no instance for the given
    account/region returns StackInstanceNotFoundException; DescribeStackRefactor on an
    unknown refactor id returns StackRefactorNotFoundException."""
    cfn = ctx.client("cloudformation")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    stackset_name = ctx.unique_name("sim2real-ssnotfound-")
    template = json.dumps({"Resources": {"Topic": {"Type": "AWS::SNS::Topic"}}})

    cfn.create_stack_set(
        StackSetName=stackset_name,
        TemplateBody=template,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _swallow(lambda: cfn.delete_stack_set(StackSetName=stackset_name)))

    code, msg = _error_code(
        lambda: cfn.describe_stack_instance(
            StackSetName=stackset_name,
            StackInstanceAccount=account,
            StackInstanceRegion=ctx.region,
        )
    )
    assert code == "StackInstanceNotFoundException", (
        f"DescribeStackInstance on a stack set with no instances: expected "
        f"StackInstanceNotFoundException, got {code!r}"
    )
    assert msg == "StackInstance not found", msg

    fake_refactor_id = str(uuid.uuid4())
    code2, msg2 = _error_code(lambda: cfn.describe_stack_refactor(StackRefactorId=fake_refactor_id))
    assert code2 == "StackRefactorNotFoundException", (
        f"DescribeStackRefactor(StackRefactorId=<unknown>): expected "
        f"StackRefactorNotFoundException, got {code2!r}"
    )
    assert msg2 == f"Stack refactor [{fake_refactor_id}] does not exist", msg2


def _error_code(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _swallow(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StackSetNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
