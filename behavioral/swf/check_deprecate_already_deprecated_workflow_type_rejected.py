"""deprecate-already-deprecated-workflow-type-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deprecate-already-deprecated-workflow-type-rejected"
GROUP = "negative-classes"
SERVICES = ["swf"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeprecateWorkflowType on an already-DEPRECATED type returns TypeDeprecatedFault and leaves it unchanged."""
    swf = ctx.client("swf")
    domain = _shared_domain(ctx)

    wt_name = ctx.unique_name("sim2real-behav-wt-")
    swf.register_workflow_type(domain=domain, name=wt_name, version="1.0")
    workflow_type = {"name": wt_name, "version": "1.0"}
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "workflow", workflow_type))

    swf.deprecate_workflow_type(domain=domain, workflowType=workflow_type)
    info = swf.describe_workflow_type(domain=domain, workflowType=workflow_type)
    assert info["typeInfo"]["status"] == "DEPRECATED", (
        f"positive control: expected DEPRECATED, got {info['typeInfo']['status']}"
    )

    code, message = _error(lambda: swf.deprecate_workflow_type(domain=domain, workflowType=workflow_type))
    assert code == "TypeDeprecatedFault", f"expected TypeDeprecatedFault, got {code!r}"
    assert message == f"WorkflowType=[name={wt_name}, version=1.0]", message

    # Effect absent: the rejected second deprecation left the type's status unchanged.
    info_after = swf.describe_workflow_type(domain=domain, workflowType=workflow_type)
    assert info_after["typeInfo"]["status"] == "DEPRECATED", (
        f"expected status unchanged at DEPRECATED, got {info_after['typeInfo']['status']}"
    )

    # Restore: UndeprecateWorkflowType moves the identical type back to REGISTERED.
    swf.undeprecate_workflow_type(domain=domain, workflowType=workflow_type)
    restored_info = swf.describe_workflow_type(domain=domain, workflowType=workflow_type)
    assert restored_info["typeInfo"]["status"] == "REGISTERED", (
        f"restore: expected REGISTERED, got {restored_info['typeInfo']['status']}"
    )

    # The identical call now succeeds on the identical type.
    swf.deprecate_workflow_type(domain=domain, workflowType=workflow_type)
    final_info = swf.describe_workflow_type(domain=domain, workflowType=workflow_type)
    assert final_info["typeInfo"]["status"] == "DEPRECATED", (
        f"post-restore deprecate: expected DEPRECATED, got {final_info['typeInfo']['status']}"
    )


def _error(fn):
    """The (code, message) of the ClientError ``fn`` raises. An unexpected success raises, so an
    emulator accepting a call AWS refuses is never read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


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
