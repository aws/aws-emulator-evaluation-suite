"""undeprecate-active-activity-type-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "undeprecate-active-activity-type-rejected"
GROUP = "negative-classes"
SERVICES = ["swf"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UndeprecateActivityType on a currently-REGISTERED (not deprecated) type returns TypeAlreadyExistsFault."""
    swf = ctx.client("swf")
    domain = _shared_domain(ctx)

    at_name = ctx.unique_name("sim2real-behav-at-")
    swf.register_activity_type(domain=domain, name=at_name, version="1.0")
    activity_type = {"name": at_name, "version": "1.0"}
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "activity", activity_type))

    code, message = _error(lambda: swf.undeprecate_activity_type(domain=domain, activityType=activity_type))
    assert code == "TypeAlreadyExistsFault", f"expected TypeAlreadyExistsFault, got {code!r}"
    expected = f"ActivityType=[name={at_name}, version=1.0]"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: status remains REGISTERED, unaffected by the rejected call.
    info = swf.describe_activity_type(domain=domain, activityType=activity_type)
    status = info["typeInfo"]["status"]
    assert status == "REGISTERED", f"expected status REGISTERED after rejected call, got {status!r}"

    # Positive control: deprecate-then-undeprecate a fresh type transitions it back to REGISTERED.
    control_name = ctx.unique_name("sim2real-behav-at-ctl-")
    swf.register_activity_type(domain=domain, name=control_name, version="1.0")
    control_type = {"name": control_name, "version": "1.0"}
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "activity", control_type))
    swf.deprecate_activity_type(domain=domain, activityType=control_type)
    swf.undeprecate_activity_type(domain=domain, activityType=control_type)
    control_info = swf.describe_activity_type(domain=domain, activityType=control_type)
    control_status = control_info["typeInfo"]["status"]
    assert control_status == "REGISTERED", (
        f"positive control: expected status REGISTERED after deprecate+undeprecate, got {control_status!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


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
