"""delete-non-deprecated-workflow-type-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-non-deprecated-workflow-type-rejected"
GROUP = "negative-classes"
SERVICES = ["swf"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteWorkflowType on a never-deprecated type is rejected with TypeNotDeprecatedFault, the type
    survives, and deprecating the identical type is what unlocks the identical delete call."""
    swf = ctx.client("swf")
    domain = _shared_domain(ctx)

    # Positive control: deprecate-then-delete on its own type succeeds and the type is gone.
    control_name = ctx.unique_name("sim2real-behav-wt-ctl-")
    swf.register_workflow_type(domain=domain, name=control_name, version="1.0")
    control_type = {"name": control_name, "version": "1.0"}
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "workflow", control_type))
    swf.deprecate_workflow_type(domain=domain, workflowType=control_type)
    control_info = swf.describe_workflow_type(domain=domain, workflowType=control_type)
    assert control_info["typeInfo"]["status"] == "DEPRECATED", (
        f"positive control: expected DEPRECATED, got {control_info['typeInfo']['status']!r}"
    )
    swf.delete_workflow_type(domain=domain, workflowType=control_type)
    deleted_code, deleted_message = _error(lambda: swf.describe_workflow_type(domain=domain, workflowType=control_type))
    assert deleted_code == "UnknownResourceFault", (
        f"positive control: expected UnknownResourceFault after delete, got {deleted_code!r}"
    )
    assert deleted_message == f"Unknown type: WorkflowType=[name={control_name}, version=1.0]", deleted_message

    # Break exactly one thing: a type that has never been deprecated.
    wt_name = ctx.unique_name("sim2real-behav-wt-")
    swf.register_workflow_type(domain=domain, name=wt_name, version="1.0")
    workflow_type = {"name": wt_name, "version": "1.0"}
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "workflow", workflow_type))

    code, message = _error(lambda: swf.delete_workflow_type(domain=domain, workflowType=workflow_type))
    assert code == "TypeNotDeprecatedFault", f"expected TypeNotDeprecatedFault, got {code!r}"
    assert message == "The type is currently registered and cannot be deleted in its current state", message

    # Effect absent: the type still exists and is still REGISTERED.
    info = swf.describe_workflow_type(domain=domain, workflowType=workflow_type)
    assert info["typeInfo"]["status"] == "REGISTERED", (
        f"expected REGISTERED after rejected delete, got {info['typeInfo']['status']!r}"
    )

    # Restore: deprecating the identical type is what unlocks it.
    swf.deprecate_workflow_type(domain=domain, workflowType=workflow_type)
    restored_info = swf.describe_workflow_type(domain=domain, workflowType=workflow_type)
    assert restored_info["typeInfo"]["status"] == "DEPRECATED", (
        f"restore: expected DEPRECATED, got {restored_info['typeInfo']['status']!r}"
    )

    # The identical delete call, on the identical type, now succeeds.
    swf.delete_workflow_type(domain=domain, workflowType=workflow_type)
    final_code, final_message = _error(lambda: swf.describe_workflow_type(domain=domain, workflowType=workflow_type))
    assert final_code == "UnknownResourceFault", (
        f"post-restore delete: expected UnknownResourceFault, got {final_code!r}"
    )
    assert final_message == f"Unknown type: WorkflowType=[name={wt_name}, version=1.0]", final_message


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
