"""user-journey-lifecycle-is-recorded-in-system-events."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "user-journey-lifecycle-is-recorded-in-system-events"
GROUP = "system-events"
SERVICES = ["resiliencehubv2"]


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


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _create_policy(ctx, rh, **kwargs) -> dict:
    """A resilience policy deleted at teardown."""
    policy = rh.create_policy(name=ctx.unique_name("sim2real-behav-rhv2-pol-"), **kwargs)["policy"]
    arn = policy["policyArn"]
    ctx.on_cleanup(_teardown(lambda: rh.delete_policy(policyArn=arn), "ResourceNotFoundException"))
    return policy


def _create_system(ctx, rh, **kwargs) -> dict:
    """A system deleted at teardown."""
    system = rh.create_system(name=ctx.unique_name("sim2real-behav-rhv2-sys-"), **kwargs)["system"]
    arn = system["systemArn"]
    ctx.on_cleanup(_teardown(lambda: rh.delete_system(systemArn=arn), "ResourceNotFoundException"))
    return system


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
    """Creating a journey with a policy, renaming it and deleting it appends system events for each
    step, the policy's association at creation and disassociation at deletion naming the policy.
    """
    rh = ctx.client("resiliencehubv2")
    policy = _create_policy(ctx, rh, availabilitySlo={"target": 99.9})
    system = _create_system(ctx, rh)
    sarn = system["systemArn"]
    jid = rh.create_user_journey(systemArn=sarn, name="checkout",
                                 policyArn=policy["policyArn"])["userJourney"]["userJourneyId"]
    rh.update_user_journey(systemArn=sarn, userJourneyId=jid, name="purchase")
    rh.delete_user_journey(systemArn=sarn, userJourneyId=jid)
    kinds = {"SYSTEM_CREATED", "SYSTEM_USER_JOURNEY_CREATED", "SYSTEM_POLICY_ASSOCIATED",
             "SYSTEM_USER_JOURNEY_UPDATED", "SYSTEM_USER_JOURNEY_DELETED", "SYSTEM_POLICY_DISASSOCIATED"}

    def page(token):
        return rh.list_system_events(systemArn=sarn, **({"nextToken": token} if token else {}))

    events = _await_events(ctx, page, lambda evs: {e["eventType"] for e in evs} >= kinds,
                           "the journey lifecycle events appearing")
    by_type = {}
    for e in events:
        by_type.setdefault(e["eventType"], []).append(e)
    assert set(by_type) == kinds, f"expected exactly {sorted(kinds)!r}, got {sorted(by_type)!r}"
    created = by_type["SYSTEM_CREATED"][0]["eventDetails"]
    assert created["description"] == f"{system['name']} system created", f"SYSTEM_CREATED: {created!r}"
    journey = by_type["SYSTEM_USER_JOURNEY_CREATED"][0]["eventDetails"]["eventMetadata"]
    assert journey == {"systemUserJourneyCreated": {"userJourneyName": "checkout"}}, f"journey created: {journey!r}"
    assoc = by_type["SYSTEM_POLICY_ASSOCIATED"][0]["eventDetails"]["eventMetadata"]["systemPolicyAssociated"]
    assert assoc["policyName"] == policy["name"], f"policy association names the policy, got {assoc.get('policyName')!r}"
    dropped = by_type["SYSTEM_POLICY_DISASSOCIATED"][0]["eventDetails"]["eventMetadata"]["systemPolicyDisassociated"]
    assert dropped["policyName"] == policy["name"], f"policy disassociation names the policy, got {dropped.get('policyName')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
