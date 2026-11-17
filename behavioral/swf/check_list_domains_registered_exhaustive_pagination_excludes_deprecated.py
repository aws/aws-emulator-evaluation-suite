"""list-domains-registered-exhaustive-pagination-excludes-deprecated."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _list_all(swf, *, status: str, page_size: int) -> list[str]:
    """Every domain name across every page of ListDomains for ``status``, following
    nextPageToken to exhaustion."""
    names: list[str] = []
    token = None
    for _ in range(1000):
        kwargs = {"registrationStatus": status, "maximumPageSize": page_size}
        if token:
            kwargs["nextPageToken"] = token
        page = swf.list_domains(**kwargs)
        names.extend(d["name"] for d in page["domainInfos"])
        token = page.get("nextPageToken") or None
        if not token:
            return names
    raise AssertionError(f"ListDomains({status!r}) pagination did not terminate")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


CHECK = "list-domains-registered-exhaustive-pagination-excludes-deprecated"
GROUP = "listing"
SERVICES = ["swf"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDomains REGISTERED, paginated at maximumPageSize 1 to exhaustion, lists a
    just-registered domain exactly once with no page repeating an entry, while ListDomains
    DEPRECATED excludes that same, still-registered domain.
    """
    swf = ctx.client("swf")
    domain = ctx.unique_name("sim2real-behav-listdom-")
    swf.register_domain(
        name=domain,
        workflowExecutionRetentionPeriodInDays="1",
        tags=[{"key": "sim2real", "value": "list-domains-registered-exhaustive"}],
    )
    # SWF has no DeleteDomain: a deprecated domain stays in the account and counts toward its
    # registered-domain quota.
    ctx.on_cleanup(_teardown(lambda: swf.deprecate_domain(name=domain),
                              "DomainDeprecatedFault", "UnknownResourceFault"))

    deadline = time.monotonic() + 30.0
    registered = _list_all(swf, status="REGISTERED", page_size=1)
    while domain not in registered and time.monotonic() < deadline:
        time.sleep(2.0)
        registered = _list_all(swf, status="REGISTERED", page_size=1)

    assert len(registered) == len(set(registered)), (
        f"paginating ListDomains(REGISTERED) at maximumPageSize=1 repeated an entry: {registered}"
    )
    assert registered.count(domain) == 1, (
        f"the just-registered domain {domain!r} appeared {registered.count(domain)} time(s) "
        f"across the exhaustive REGISTERED pagination, expected exactly 1"
    )

    deprecated = _list_all(swf, status="DEPRECATED", page_size=100)
    assert domain not in deprecated, (
        f"the still-registered domain {domain!r} appeared in ListDomains(DEPRECATED): {deprecated}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
