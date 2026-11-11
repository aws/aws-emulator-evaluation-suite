"""deprecate-already-deprecated-activity-type-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deprecate-already-deprecated-activity-type-rejected"
GROUP = "negative-classes"
SERVICES = ["swf"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Calling DeprecateActivityType a second time on an already-DEPRECATED type fails with
    TypeDeprecatedFault; undeprecating then re-issuing the identical deprecate call on the same
    type succeeds, proving the rejection is not permanent."""
    swf = ctx.client("swf")
    domain = _shared_domain(ctx)

    act_name = ctx.unique_name("sim2real-swf-act-")
    version = "1.0"
    swf.register_activity_type(domain=domain, name=act_name, version=version, defaultTaskList={"name": "default"})
    activity_type = {"name": act_name, "version": version}
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "activity", activity_type))

    swf.deprecate_activity_type(domain=domain, activityType=activity_type)
    desc = swf.describe_activity_type(domain=domain, activityType=activity_type)
    assert desc["typeInfo"]["status"] == "DEPRECATED", (
        f"expected DEPRECATED after first deprecate, got {desc['typeInfo']['status']!r}"
    )
    first_deprecation_date = desc["typeInfo"]["deprecationDate"]

    code, message = _error(lambda: swf.deprecate_activity_type(domain=domain, activityType=activity_type))
    assert code == "TypeDeprecatedFault", f"expected TypeDeprecatedFault on re-deprecate, got {code!r}"
    assert message == f"ActivityType=[name={act_name}, version={version}]", message

    # effect absent: status and deprecation timestamp are unchanged by the rejected call
    desc2 = swf.describe_activity_type(domain=domain, activityType=activity_type)
    assert desc2["typeInfo"]["status"] == "DEPRECATED", (
        f"expected DEPRECATED unchanged after rejected call, got {desc2['typeInfo']['status']!r}"
    )
    assert desc2["typeInfo"]["deprecationDate"] == first_deprecation_date, (
        f"expected deprecationDate unchanged at {first_deprecation_date!r}, "
        f"got {desc2['typeInfo']['deprecationDate']!r}"
    )

    # restore: undeprecate the same activity type, then re-issue the identical deprecate
    # call that was just rejected — it must succeed now that the state allows it again
    swf.undeprecate_activity_type(domain=domain, activityType=activity_type)
    desc3 = swf.describe_activity_type(domain=domain, activityType=activity_type)
    assert desc3["typeInfo"]["status"] == "REGISTERED", (
        f"expected REGISTERED after undeprecate, got {desc3['typeInfo']['status']!r}"
    )

    swf.deprecate_activity_type(domain=domain, activityType=activity_type)
    desc4 = swf.describe_activity_type(domain=domain, activityType=activity_type)
    assert desc4["typeInfo"]["status"] == "DEPRECATED", (
        f"expected the identical deprecate call to succeed after restore, got {desc4['typeInfo']['status']!r}"
    )

    # positive control: a fresh activity type deprecates successfully on its first call
    act_name2 = ctx.unique_name("sim2real-swf-act2-")
    swf.register_activity_type(domain=domain, name=act_name2, version=version, defaultTaskList={"name": "default"})
    activity_type2 = {"name": act_name2, "version": version}
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "activity", activity_type2))
    swf.deprecate_activity_type(domain=domain, activityType=activity_type2)
    desc5 = swf.describe_activity_type(domain=domain, activityType=activity_type2)
    assert desc5["typeInfo"]["status"] == "DEPRECATED", (
        f"expected fresh control type DEPRECATED, got {desc5['typeInfo']['status']!r}"
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


def _error(fn):
    """The (code, message) of the ClientError ``fn`` raises. An unexpected success raises, so an
    emulator accepting a call AWS refuses is never read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
