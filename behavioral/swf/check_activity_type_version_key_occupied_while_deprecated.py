"""activity-type-version-key-occupied-while-deprecated."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "activity-type-version-key-occupied-while-deprecated"
GROUP = "negative-classes"
SERVICES = ["swf"]

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
        if exc.response["Error"]["Code"] != "DomainAlreadyExistsFault":
            raise
    return _SHARED_DOMAIN


def _delete_type(swf, domain: str, activity_type: dict) -> None:
    """Teardown: deprecate then delete an activity type; already deprecated or gone is fine."""
    try:
        swf.deprecate_activity_type(domain=domain, activityType=activity_type)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("TypeDeprecatedFault", "UnknownResourceFault"):
            raise
    try:
        swf.delete_activity_type(domain=domain, activityType=activity_type)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "UnknownResourceFault":
            raise


def _error(fn):
    """The (code, message) of the ClientError ``fn`` raises. An unexpected success raises, so an
    accepted call AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A deprecated activity type's (name, version) key still refuses RegisterActivityType and
    Describe still reports its original defaults; a new version registers; deleting the
    deprecated version frees the key for a re-registration with its own new defaults."""
    swf = ctx.client("swf")
    domain = _shared_domain(ctx)
    name = ctx.unique_name("sim2real-behav-at-")

    original = {"name": name, "version": "1.0"}
    swf.register_activity_type(
        domain=domain,
        name=name,
        version="1.0",
        defaultTaskList={"name": "sim2real-behav-tl-original"},
        defaultTaskScheduleToStartTimeout="60",
        defaultTaskStartToCloseTimeout="300",
        defaultTaskScheduleToCloseTimeout="NONE",
        defaultTaskHeartbeatTimeout="NONE",
    )
    ctx.on_cleanup(lambda: _delete_type(swf, domain, original))

    swf.deprecate_activity_type(domain=domain, activityType=original)

    deprecated = swf.describe_activity_type(domain=domain, activityType=original)
    assert deprecated["typeInfo"]["status"] == "DEPRECATED", deprecated["typeInfo"]
    cfg = deprecated["configuration"]
    assert cfg["defaultTaskList"]["name"] == "sim2real-behav-tl-original", cfg
    assert cfg["defaultTaskScheduleToStartTimeout"] == "60", cfg
    assert cfg["defaultTaskStartToCloseTimeout"] == "300", cfg

    code, message = _error(
        lambda: swf.register_activity_type(domain=domain, name=name, version="1.0")
    )
    assert code == "TypeAlreadyExistsFault", code
    assert message == f"ActivityType=[name={name}, version=1.0]", message

    # Legal neighbour: a new version of the same name registers while the original stays deprecated.
    new_version = {"name": name, "version": "2.0"}
    swf.register_activity_type(
        domain=domain,
        name=name,
        version="2.0",
        defaultTaskList={"name": "sim2real-behav-tl-v2"},
        defaultTaskScheduleToStartTimeout="90",
        defaultTaskStartToCloseTimeout="400",
        defaultTaskScheduleToCloseTimeout="NONE",
        defaultTaskHeartbeatTimeout="NONE",
    )
    ctx.on_cleanup(lambda: _delete_type(swf, domain, new_version))

    v2 = swf.describe_activity_type(domain=domain, activityType=new_version)
    assert v2["typeInfo"]["status"] == "REGISTERED", v2["typeInfo"]
    v2_cfg = v2["configuration"]
    assert v2_cfg["defaultTaskList"]["name"] == "sim2real-behav-tl-v2", v2_cfg
    assert v2_cfg["defaultTaskScheduleToStartTimeout"] == "90", v2_cfg

    # Deleting the deprecated version releases its key.
    swf.delete_activity_type(domain=domain, activityType=original)
    gone_code, gone_message = _error(
        lambda: swf.describe_activity_type(domain=domain, activityType=original)
    )
    assert gone_code == "UnknownResourceFault", gone_code
    assert gone_message == f"Unknown type: ActivityType=[name={name}, version=1.0]", gone_message

    # The released (name, version) key accepts a fresh registration with its own new defaults.
    swf.register_activity_type(
        domain=domain,
        name=name,
        version="1.0",
        defaultTaskList={"name": "sim2real-behav-tl-reborn"},
        defaultTaskScheduleToStartTimeout="120",
        defaultTaskStartToCloseTimeout="500",
        defaultTaskScheduleToCloseTimeout="NONE",
        defaultTaskHeartbeatTimeout="NONE",
    )
    ctx.on_cleanup(lambda: _delete_type(swf, domain, original))

    reborn = swf.describe_activity_type(domain=domain, activityType=original)
    assert reborn["typeInfo"]["status"] == "REGISTERED", reborn["typeInfo"]
    reborn_cfg = reborn["configuration"]
    assert reborn_cfg["defaultTaskList"]["name"] == "sim2real-behav-tl-reborn", reborn_cfg
    assert reborn_cfg["defaultTaskScheduleToStartTimeout"] == "120", reborn_cfg
    assert reborn_cfg["defaultTaskStartToCloseTimeout"] == "500", reborn_cfg


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
