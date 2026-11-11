"""service-events-type-filter-and-pages-partition-the-log."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "service-events-type-filter-and-pages-partition-the-log"
GROUP = "service-events"
SERVICES = ["resiliencehubv2"]

_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "resiliencehub.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()``; only the resource's own not-found codes mean it is gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn()`` raises; a success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _invoker_role(ctx, iam) -> str:
    """An IAM role resiliencehub may assume, deleted at teardown."""
    name = ctx.unique_name("sim2real-behav-rhv2-role-")
    iam.create_role(RoleName=name, AssumeRolePolicyDocument=_TRUST)
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    return name


def _create_service(ctx, rh, role: str, **kwargs) -> dict:
    """CreateService, retried only while IAM has not yet made the new invoker role assumable."""
    kwargs.setdefault("name", ctx.unique_name("sim2real-behav-rhv2-svc-"))
    unassumable = (
        f"Cannot assume invoker role '{role}'. Ensure the role exists and its trust policy "
        "allows access."
    )
    deadline = time.monotonic() + _budget_s(ctx, 120.0)
    while True:
        try:
            service = rh.create_service(
                regions=[ctx.region], permissionModel={"invokerRoleName": role}, **kwargs
            )["service"]
            break
        except ClientError as exc:
            if exc.response["Error"].get("Message") != unassumable:
                raise
            if time.monotonic() >= deadline:
                if _budget_spent(ctx):
                    raise TimeoutError("invoker role becoming assumable: the run budget ended first; not graded") from exc
                raise
        # IAM propagation exposes no condition to poll; the retry above is what waits.
        time.sleep(5)
    arn = service["serviceArn"]
    ctx.on_cleanup(_teardown(lambda: rh.delete_service(serviceArn=arn), "ResourceNotFoundException"))
    return service


def _await_events(ctx, list_page, want, describe: str) -> list:
    """Every event ``list_page(token)`` pages through, polled until ``want(events)`` holds."""
    deadline = time.monotonic() + _budget_s(ctx, 60.0)
    while True:
        events, token = [], None
        while True:
            page = list_page(token)
            events.extend(page["events"])
            token = page.get("nextToken")
            if not token:
                break
        if want(events):
            return events
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"{describe}: the run budget ended first; not graded")
            raise AssertionError(f"{describe} never held; events were {[e['eventType'] for e in events]!r}")
        time.sleep(2)


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Paging ListServiceEvents one event at a time yields exactly the unpaged log, and an
    eventTypes filter yields exactly the matching subset of it.
    """
    rh = ctx.client("resiliencehubv2")
    role = _invoker_role(ctx, ctx.client("iam"))
    arn = _create_service(ctx, rh, role)["serviceArn"]
    for name in ("checkout", "search"):
        rh.create_service_function(serviceArn=arn, name=name, criticality="PRIMARY")
    rh.create_assertion(serviceArn=arn, text="Degrades gracefully.")
    want = {"SERVICE_CREATED", "SERVICE_FUNCTION_CREATED", "ASSERTION_CREATED"}

    def whole(token):
        return rh.list_service_events(serviceArn=arn, **({"nextToken": token} if token else {}))

    full = _await_events(ctx, whole, lambda evs: len(evs) >= 4 and {e["eventType"] for e in evs} >= want,
                         "the service, two function and one assertion events appearing")
    ids = [e["eventId"] for e in full]
    assert len(ids) == len(set(ids)) == 4, f"expected 4 distinct events, got {[e['eventType'] for e in full]!r}"

    paged, token, pages = [], None, 0
    while True:
        page = rh.list_service_events(serviceArn=arn, maxResults=1, **({"nextToken": token} if token else {}))
        assert len(page["events"]) <= 1, f"maxResults=1 returned {len(page['events'])} events"
        paged.extend(e["eventId"] for e in page["events"])
        pages += 1
        token = page.get("nextToken")
        if not token or pages > 20:
            break
    assert sorted(paged) == sorted(ids), "pages of one must cover the unpaged log exactly once"

    only = rh.list_service_events(serviceArn=arn, eventTypes=["SERVICE_FUNCTION_CREATED"])["events"]
    expected = sorted(e["eventId"] for e in full if e["eventType"] == "SERVICE_FUNCTION_CREATED")
    assert sorted(e["eventId"] for e in only) == expected and len(expected) == 2, (
        f"the filter must return exactly the two function events, got {[e['eventType'] for e in only]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
