"""list-activity-types-exact-pagination-and-reverse-order."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

_TASK_LIST = "sim2real-behav-tl"


def _register_activity_type(ctx, swf, domain, name, version):
    swf.register_activity_type(
        domain=domain,
        name=name,
        version=version,
        defaultTaskList={"name": _TASK_LIST},
        defaultTaskScheduleToStartTimeout="60",
        defaultTaskStartToCloseTimeout="300",
        defaultTaskScheduleToCloseTimeout="NONE",
        defaultTaskHeartbeatTimeout="NONE",
    )
    ref = {"name": name, "version": version}
    ctx.on_cleanup(lambda: _delete_type(swf, domain, "activity", ref))


def _paginate(swf, domain, name, *, reverse: bool) -> list[list[str]]:
    pages: list[list[str]] = []
    token = None
    for _ in range(10):
        kwargs = dict(domain=domain, name=name, registrationStatus="REGISTERED", maximumPageSize=2)
        if reverse:
            kwargs["reverseOrder"] = True
        if token:
            kwargs["nextPageToken"] = token
        page = swf.list_activity_types(**kwargs)
        pages.append([t["activityType"]["version"] for t in page["typeInfos"]])
        token = page.get("nextPageToken") or None
        if not token:
            return pages
    raise AssertionError("pagination did not terminate within 10 pages")


CHECK = "list-activity-types-exact-pagination-and-reverse-order"
GROUP = "listing"
SERVICES = ["swf"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListActivityTypes over 5 versions of one name at maximumPageSize 2 returns pages of
    exactly 2, 2, 1 with a nextPageToken on each non-final page and none on the last, every
    version exactly once in ascending version order, and in descending order with reverseOrder.
    """
    swf = ctx.client("swf")
    domain = _shared_domain(ctx)
    name = ctx.unique_name("sim2real-behav-exactpageact-")
    versions = [f"{i}.0" for i in range(5)]
    for version in versions:
        _register_activity_type(ctx, swf, domain, name, version)

    forward = _paginate(swf, domain, name, reverse=False)
    assert [len(p) for p in forward] == [2, 2, 1], (
        f"forward page sizes were {[len(p) for p in forward]}, expected [2, 2, 1]"
    )
    flat_forward = [v for page in forward for v in page]
    assert flat_forward == versions, f"forward order was {flat_forward}, expected {versions}"

    backward = _paginate(swf, domain, name, reverse=True)
    assert [len(p) for p in backward] == [2, 2, 1], (
        f"reverseOrder page sizes were {[len(p) for p in backward]}, expected [2, 2, 1]"
    )
    flat_backward = [v for page in backward for v in page]
    assert flat_backward == list(reversed(versions)), (
        f"reverseOrder order was {flat_backward}, expected {list(reversed(versions))}"
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
