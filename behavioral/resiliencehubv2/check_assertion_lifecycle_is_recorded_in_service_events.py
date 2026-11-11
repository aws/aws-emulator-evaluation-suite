"""assertion-lifecycle-is-recorded-in-service-events."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assertion-lifecycle-is-recorded-in-service-events"
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
    """Creating, editing and deleting an assertion each append one service event naming the
    assertion, with the text the assertion carried at that moment.
    """
    rh = ctx.client("resiliencehubv2")
    role = _invoker_role(ctx, ctx.client("iam"))
    arn = _create_service(ctx, rh, role)["serviceArn"]
    aid = rh.create_assertion(serviceArn=arn, text="Survives a zonal outage.")["assertion"]["assertionId"]
    rh.update_assertion(serviceArn=arn, assertionId=aid, text="Survives a Regional outage.")
    rh.delete_assertion(serviceArn=arn, assertionId=aid)
    kinds = {"ASSERTION_CREATED", "ASSERTION_UPDATED", "ASSERTION_DELETED"}

    def page(token):
        kwargs = {"serviceArn": arn, "eventTypes": sorted(kinds)}
        return rh.list_service_events(**kwargs, **({"nextToken": token} if token else {}))

    events = _await_events(ctx, page, lambda evs: {e["eventType"] for e in evs} >= kinds,
                           "the three assertion events appearing")
    by_type = {}
    for e in events:
        by_type.setdefault(e["eventType"], []).append(e)
    counts = {k: len(v) for k, v in by_type.items()}
    assert counts == {k: 1 for k in kinds}, f"expected one event per kind, got {counts!r}"
    meta = {
        "ASSERTION_CREATED": ("assertionCreated", "Survives a zonal outage."),
        "ASSERTION_UPDATED": ("assertionUpdated", "Survives a Regional outage."),
        "ASSERTION_DELETED": ("assertionDeleted", "Assertion deleted"),
    }
    for kind, (key, description) in meta.items():
        event = by_type[kind][0]
        assert event["serviceArn"] == arn, f"{kind} must name the service"
        details = event["eventDetails"]
        assert details["eventMetadata"] == {key: {"assertionId": aid}}, f"{kind} metadata: {details['eventMetadata']!r}"
        assert details["description"] == description, f"{kind} description: {details['description']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
