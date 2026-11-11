"""undeprecate-active-workflow-type-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "undeprecate-active-workflow-type-rejected"
GROUP = "negative-classes"
SERVICES = ["swf"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UndeprecateWorkflowType on a currently-REGISTERED (not deprecated) type returns
    TypeAlreadyExistsFault; deprecating that SAME type and retrying the identical call succeeds."""
    swf = ctx.client("swf")
    domain = _shared_domain(ctx)

    wt_name = ctx.unique_name("sim2real-behav-wt-")
    swf.register_workflow_type(domain=domain, name=wt_name, version="1.0")
    workflow_type = {"name": wt_name, "version": "1.0"}
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "workflow", workflow_type))

    code, message = _error(lambda: swf.undeprecate_workflow_type(domain=domain, workflowType=workflow_type))
    assert code == "TypeAlreadyExistsFault", (
        f"expected TypeAlreadyExistsFault undeprecating a REGISTERED (not deprecated) workflow "
        f"type, got {code!r}"
    )
    expected = f"WorkflowType=[name={wt_name}, version=1.0]"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the rejected call left status untouched.
    info = swf.describe_workflow_type(domain=domain, workflowType=workflow_type)
    assert info["typeInfo"]["status"] == "REGISTERED", (
        f"expected status REGISTERED after the rejected UndeprecateWorkflowType call, "
        f"got {info['typeInfo']['status']!r}"
    )

    # Restore, then retry the IDENTICAL call: deprecating this same type is what makes
    # UndeprecateWorkflowType on it valid.
    swf.deprecate_workflow_type(domain=domain, workflowType=workflow_type)
    _wait_for_status(swf, domain, workflow_type, "DEPRECATED")
    swf.undeprecate_workflow_type(domain=domain, workflowType=workflow_type)
    restored = swf.describe_workflow_type(domain=domain, workflowType=workflow_type)
    assert restored["typeInfo"]["status"] == "REGISTERED", (
        f"expected status REGISTERED after UndeprecateWorkflowType on a DEPRECATED type, "
        f"got {restored['typeInfo']['status']!r}"
    )


def _error(fn):
    """The AWS error (code, message) for a call that MUST fail. An unexpected SUCCESS raises rather
    than returning a falsy sentinel: an emulator accepting a call real AWS rejects is the strongest
    signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"expected UndeprecateWorkflowType to be refused on a REGISTERED (not deprecated) "
        f"workflow type, but it SUCCEEDED and returned {result!r}"
    )


def _wait_for_status(swf, domain, workflow_type, want, timeout=60, interval=2):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = swf.describe_workflow_type(domain=domain, workflowType=workflow_type)["typeInfo"]["status"]
        if last == want:
            return
        time.sleep(interval)
    raise AssertionError(
        f"workflow type {workflow_type} status {last!r} never reached {want!r} within {timeout}s"
    )


_SHARED_DOMAIN = "sim2real-swf-shared"


def _shared_domain(ctx) -> str:
    """The account's shared SWF domain, registered if absent and never deprecated: SWF has no
    DeleteDomain, and a deprecated domain counts toward the registered-domain quota."""
    swf = ctx.client("swf")
    try:
        status = swf.describe_domain(name=_SHARED_DOMAIN)["domainInfo"]["status"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "UnknownResourceFault":
            raise
        status = None
    try:
        if status is None:
            swf.register_domain(
                name=_SHARED_DOMAIN,
                workflowExecutionRetentionPeriodInDays="1",
                tags=[{"key": "sim2real:infra", "value": "swf-shared"}],
            )
        elif status == "DEPRECATED":
            swf.undeprecate_domain(name=_SHARED_DOMAIN)
    except ClientError as exc:
        # A concurrent run registered or restored it first.
        if exc.response["Error"]["Code"] != "DomainAlreadyExistsFault":
            raise
    return _SHARED_DOMAIN


def _delete_type(swf, domain: str, kind: str, type_ref: dict) -> None:
    """Teardown: deprecate then delete a workflow or activity type (``kind``), which the shared
    domain would otherwise keep; a type already deprecated or gone is fine."""
    arg = {"workflow": "workflowType", "activity": "activityType"}[kind]
    try:
        getattr(swf, f"deprecate_{kind}_type")(domain=domain, **{arg: type_ref})
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("TypeDeprecatedFault", "UnknownResourceFault"):
            raise
    try:
        getattr(swf, f"delete_{kind}_type")(domain=domain, **{arg: type_ref})
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "UnknownResourceFault":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
