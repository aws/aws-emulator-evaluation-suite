"""foreach-resources-without-language-extensions-transform-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "foreach-resources-without-language-extensions-transform-rejected"
GROUP = 'language_extensions'
SERVICES = ['cloudformation']

_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
}


_FOREACH_MALFORMED = (
    "ValidationError",
    "Template format error: [/Resources/Fn::ForEach::Items] resource definition is malformed",
)


def _describe(cf, name):
    """DescribeStacks for one stack, or None when AWS reports it does not exist."""
    try:
        return cf.describe_stacks(StackName=name)["Stacks"][0]
    except ClientError as exc:
        err = exc.response["Error"]
        if (err.get("Code"), err.get("Message")) == ("ValidationError", f"Stack with id {name} does not exist"):
            return None
        raise


def _wait_terminal(cf, name, *, timeout_s=300, interval_s=5):
    """Poll DescribeStacks until the stack reaches a terminal state; return the stack."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        stack = _describe(cf, name)
        last = None if stack is None else stack["StackStatus"]
        if stack is not None and last in _TERMINAL_STATES:
            return stack
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack {name} did not reach a terminal state within {timeout_s}s (last={last!r})")
        time.sleep(interval_s)


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


def _delete_stack(cf, name, *, timeout_s=600, interval_s=5):
    """Delete a stack and wait until DescribeStacks no longer finds it; raise on DELETE_FAILED."""
    cf.delete_stack(StackName=name)
    deadline = time.monotonic() + timeout_s
    while True:
        stack = _describe(cf, name)
        if stack is None or stack["StackStatus"] == "DELETE_COMPLETE":
            return
        assert stack["StackStatus"] != "DELETE_FAILED", (
            f"stack {name} failed to delete: {stack.get('StackStatusReason')!r}"
        )
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack {name} was not deleted within {timeout_s}s")
        time.sleep(interval_s)


def _delete_if_present(cf, name):
    """Delete a stack that a refused create should never have made; a no-op when it does not exist."""
    if _describe(cf, name) is not None:
        _delete_stack(cf, name)


def _resources_body():
    return {"Fn::ForEach::Items": ["Name", ["Alpha", "Beta"],
                                    {"${Name}": {"Type": "AWS::CloudFormation::WaitConditionHandle"}}]}


def _without_transform():
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": _resources_body()})


def _with_transform():
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Transform": "AWS::LanguageExtensions",
        "Resources": _resources_body(),
    })


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Fn::ForEach in Resources with no Transform: AWS::LanguageExtensions declared is refused
    up front with no stack created; the identical loop with the transform declared expands."""
    cf = ctx.client("cloudformation")

    missing_transform = ctx.unique_name("sim2real-behav-foreach-notf-")
    ctx.on_cleanup(lambda: _delete_if_present(cf, missing_transform))
    expect_error(lambda: cf.create_stack(
        StackName=missing_transform, TemplateBody=_without_transform(),
    ), *_FOREACH_MALFORMED)
    assert _describe(cf, missing_transform) is None, (
        f"the rejected create must leave no stack behind: {missing_transform}"
    )

    # positive control: the identical loop, with only the Transform added, is accepted and
    # expands into one resource per collection item, so the rejection above is specific to
    # the missing Transform, not to this check's template shape in general.
    ok = ctx.unique_name("sim2real-behav-foreach-wtf-")
    cf.create_stack(StackName=ok, TemplateBody=_with_transform(), Capabilities=["CAPABILITY_AUTO_EXPAND"])
    ctx.on_cleanup(lambda: _delete_stack(cf, ok))
    final = _wait_terminal(cf, ok)
    assert final["StackStatus"] == "CREATE_COMPLETE", (
        f"the same loop with the Transform declared must create; got {final['StackStatus']!r}: "
        f"{final.get('StackStatusReason')!r}"
    )
    ids = {
        r["LogicalResourceId"]
        for r in cf.list_stack_resources(StackName=ok)["StackResourceSummaries"]
    }
    assert ids == {"Alpha", "Beta"}, f"ForEach must expand one resource per item, got {sorted(ids)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
