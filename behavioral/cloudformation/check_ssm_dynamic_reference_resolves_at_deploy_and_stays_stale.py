"""ssm-dynamic-reference-resolves-at-deploy-and-stays-stale."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ssm-dynamic-reference-resolves-at-deploy-and-stays-stale"
GROUP = 'dynamic_references'
SERVICES = ['cloudformation']

_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
}


def _describe(cf, name):
    """DescribeStacks for one stack, or None when it does not exist."""
    try:
        return cf.describe_stacks(StackName=name)["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ValidationError":
            return None
        raise


def _wait_terminal(cf, name, *, timeout_s=600, interval_s=5):
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


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises. An unexpected success raises, naming the result."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _outputs(stack):
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}

def _template(target_latest, target_pinned, source, marker):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Latest": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {"Name": target_latest, "Type": "String", "Value": "{{resolve:ssm:" + source + "}}",
                               "Description": marker},
            },
            "Pinned": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {"Name": target_pinned, "Type": "String", "Value": "{{resolve:ssm:" + source + ":1}}",
                               "Description": marker},
            },
        },
    })

@tags("axis:happy-path", "cap:c4", "cap:c7", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A dynamic reference to an SSM parameter resolves into the provisioned resource at create; a new
    parameter version leaves the resource unchanged until a stack update touches it, after which the
    versionless reference follows the latest version and the version-pinned one stays on version 1.
    """
    cf = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    source = "/" + ctx.unique_name("sim2real-behav-dynref-src-")
    latest = "/" + ctx.unique_name("sim2real-behav-dynref-latest-")
    pinned = "/" + ctx.unique_name("sim2real-behav-dynref-pinned-")
    stack = ctx.unique_name("sim2real-behav-dynref-")

    ssm.put_parameter(Name=source, Type="String", Value="alpha")
    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=source))

    cf.create_stack(StackName=stack, TemplateBody=_template(latest, pinned, source, "sim2real one"))
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=stack))
    created = _wait_terminal(cf, stack)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE, got {created['StackStatus']!r}: {created.get('StackStatusReason')!r}"
    )
    read = lambda name: ssm.get_parameter(Name=name)["Parameter"]["Value"]  # noqa: E731
    assert read(latest) == "alpha", f"the versionless reference must resolve at create; got {read(latest)!r}"
    assert read(pinned) == "alpha", f"the version-1 reference must resolve at create; got {read(pinned)!r}"

    ssm.put_parameter(Name=source, Type="String", Value="beta", Overwrite=True)
    assert read(source) == "beta", f"the source parameter did not take its new version: {read(source)!r}"
    assert read(latest) == "alpha", f"a new parameter version must not reach the resource without an update; got {read(latest)!r}"

    cf.update_stack(StackName=stack, TemplateBody=_template(latest, pinned, source, "sim2real two"))
    updated = _wait_terminal(cf, stack)
    assert updated["StackStatus"] == "UPDATE_COMPLETE", (
        f"expected UPDATE_COMPLETE, got {updated['StackStatus']!r}: {updated.get('StackStatusReason')!r}"
    )
    assert read(latest) == "beta", f"after an update the versionless reference must follow the latest version; got {read(latest)!r}"
    assert read(pinned) == "alpha", f"a version-pinned reference must stay on version 1; got {read(pinned)!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
