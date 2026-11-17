"""create-stack-set-invalid-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-stack-set-invalid-name-rejected"
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStackSet rejects a name containing an underscore with ValidationError and the
    exact constraint message; the same prefix with hyphens only is accepted."""
    cfn = ctx.client("cloudformation")
    valid_name = ctx.unique_name("sim2real-behav-ssname-")
    invalid_name = valid_name.replace("-", "_")

    _CODE_MESSAGE = (
        "ValidationError",
        f"1 validation error detected: Value '{invalid_name}' at 'stackSetName' failed to "
        "satisfy constraint: Member must satisfy regular expression pattern: "
        "[a-zA-Z][-a-zA-Z0-9]*",
    )
    got = _error(lambda: cfn.create_stack_set(StackSetName=invalid_name, TemplateBody=_TEMPLATE))
    assert got == _CODE_MESSAGE, f"expected {_CODE_MESSAGE!r}, got {got!r}"

    created = cfn.create_stack_set(StackSetName=valid_name, TemplateBody=_TEMPLATE)
    ctx.on_cleanup(lambda: cfn.delete_stack_set(StackSetName=valid_name))
    described = cfn.describe_stack_set(StackSetName=valid_name)["StackSet"]
    assert described["StackSetId"] == created["StackSetId"], (
        f"expected DescribeStackSet to report {created['StackSetId']!r}, got "
        f"{described['StackSetId']!r}"
    )
    assert described["Status"] == "ACTIVE", (
        f"expected the legal-neighbour stack set to be ACTIVE, got {described['Status']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
