"""describe-activity-type-cross-domain-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-activity-type-cross-domain-rejected"
GROUP = "overly-permissive"
SERVICES = ["swf"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An activity type registered in one domain is invisible from a different domain --
    DescribeActivityType with the wrong domain name is rejected with UnknownResourceFault
    rather than leaking the type across the domain boundary."""
    swf = ctx.client("swf")
    home_domain = _register_domain(ctx)
    other_domain = _register_domain(ctx)

    activity_name = ctx.unique_name("sim2real-swf-act-")
    version = "1.0"
    swf.register_activity_type(
        domain=home_domain,
        name=activity_name,
        version=version,
        defaultTaskList={"name": ctx.unique_name("sim2real-swf-tl-")},
        defaultTaskStartToCloseTimeout="60",
        defaultTaskHeartbeatTimeout="60",
        defaultTaskScheduleToStartTimeout="60",
        defaultTaskScheduleToCloseTimeout="120",
    )
    ctx.on_cleanup(
        lambda: _safe(
            lambda: swf.deprecate_activity_type(domain=home_domain, activityType={"name": activity_name, "version": version})
        )
    )
    activity_type = {"name": activity_name, "version": version}

    # Positive control: describing it via the domain it was registered in succeeds.
    described = swf.describe_activity_type(domain=home_domain, activityType=activity_type)
    assert described["typeInfo"]["status"] == "REGISTERED", (
        f"expected REGISTERED right after registration, got {described['typeInfo']['status']!r}"
    )
    assert described["typeInfo"]["activityType"] == activity_type, (
        f"expected activityType {activity_type!r}, got {described['typeInfo']['activityType']!r}"
    )

    # Break exactly one thing: same name+version, but looked up via a different domain.
    code, message = _error(lambda: swf.describe_activity_type(domain=other_domain, activityType=activity_type))
    assert code == "UnknownResourceFault", f"expected UnknownResourceFault, got {code!r}"
    assert message == f"Unknown type: ActivityType=[name={activity_name}, version={version}]", message

    # Effect absent: the other domain's activity type listing does not contain it either.
    listed = swf.list_activity_types(domain=other_domain, registrationStatus="REGISTERED")
    names_in_other_domain = [t["activityType"]["name"] for t in listed["typeInfos"]]
    assert activity_name not in names_in_other_domain, "activity type leaked into an unrelated domain's listing"


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DomainDeprecatedFault",
            "TypeDeprecatedFault",
            "UnknownResourceFault",
        ):
            raise


def _register_domain(ctx) -> str:
    swf = ctx.client("swf")
    name = ctx.unique_name("sim2real-swf-dom-")
    swf.register_domain(name=name, workflowExecutionRetentionPeriodInDays="1")
    # SWF has no DeleteDomain: a deprecated domain stays in the account and counts toward its registered-domain quota.
    ctx.on_cleanup(lambda: _safe(lambda: swf.deprecate_domain(name=name)))
    return name


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
