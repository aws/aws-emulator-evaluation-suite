"""delete-non-deprecated-activity-type-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-non-deprecated-activity-type-rejected"
GROUP = "negative-classes"
SERVICES = ["swf"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteActivityType on a never-deprecated type is rejected with TypeNotDeprecatedFault, the
    type survives, and deprecating that SAME type is what unlocks the identical delete call."""
    swf = ctx.client("swf")
    domain = _shared_domain(ctx)

    at_name = ctx.unique_name("sim2real-behav-at-")
    swf.register_activity_type(domain=domain, name=at_name, version="1.0")
    activity_type = {"name": at_name, "version": "1.0"}
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "activity", activity_type))

    code, message = _error(lambda: swf.delete_activity_type(domain=domain, activityType=activity_type))
    assert code == "TypeNotDeprecatedFault", (
        f"deleting a never-deprecated activity type must be refused with TypeNotDeprecatedFault; got {code!r}"
    )
    assert message == "The type is currently registered and cannot be deleted in its current state", message

    # Effect absent: the type still exists and is still REGISTERED.
    info = swf.describe_activity_type(domain=domain, activityType=activity_type)
    assert info["typeInfo"]["status"] == "REGISTERED", (
        f"the refused delete must leave the type REGISTERED; status is {info['typeInfo']['status']!r}"
    )

    # Restore: deprecating this SAME type is exactly what the fault named as missing, so the
    # identical delete call on the identical type must now succeed and the type must be gone.
    swf.deprecate_activity_type(domain=domain, activityType=activity_type)
    swf.delete_activity_type(domain=domain, activityType=activity_type)
    restored_code, restored_message = _error(
        lambda: swf.describe_activity_type(domain=domain, activityType=activity_type)
    )
    assert restored_code == "UnknownResourceFault", (
        f"the identical type, once deprecated, must delete and disappear; describe returned {restored_code!r}"
    )
    assert restored_message == f"Unknown type: ActivityType=[name={at_name}, version=1.0]", restored_message

    # Positive control: an independently created type follows the same deprecate-then-delete path,
    # proving the account and API are otherwise healthy and the restore above is not a one-off.
    control_name = ctx.unique_name("sim2real-behav-at-ctl-")
    swf.register_activity_type(domain=domain, name=control_name, version="1.0")
    control_type = {"name": control_name, "version": "1.0"}
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "activity", control_type))
    swf.deprecate_activity_type(domain=domain, activityType=control_type)
    swf.delete_activity_type(domain=domain, activityType=control_type)
    deleted_code, deleted_message = _error(lambda: swf.describe_activity_type(domain=domain, activityType=control_type))
    assert deleted_code == "UnknownResourceFault", (
        f"the control type must also delete and disappear after deprecation; describe returned {deleted_code!r}"
    )
    assert deleted_message == f"Unknown type: ActivityType=[name={control_name}, version=1.0]", deleted_message


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
