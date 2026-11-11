"""case-event-configuration-round-trip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "case-event-configuration-round-trip"
GROUP = "data-plane"
SERVICES = ["connectcases"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutCaseEventConfiguration persists the EventBridge case-event publishing
    configuration (enabled flag, included case fields, related-item content flag) and
    GetCaseEventConfiguration returns exactly what was put."""
    cc = ctx.client("connectcases")
    domain_id = _create_active_domain(ctx)
    text_field = _create_field(ctx, domain_id, "Text", "text")

    config = {
        "enabled": True,
        "includedData": {
            "caseData": {"fields": [{"id": text_field}]},
            "relatedItemData": {"includeContent": True},
        },
    }
    cc.put_case_event_configuration(domainId=domain_id, eventBridge=config)

    got = cc.get_case_event_configuration(domainId=domain_id)["eventBridge"]
    assert got["enabled"] is True, f"expected enabled=True, got {got['enabled']!r}"
    assert got["includedData"]["caseData"]["fields"] == [{"id": text_field}], (
        f"expected caseData.fields=[{{'id': {text_field!r}}}], "
        f"got {got['includedData']['caseData']['fields']!r}"
    )
    assert got["includedData"]["relatedItemData"]["includeContent"] is True, (
        f"expected relatedItemData.includeContent=True, "
        f"got {got['includedData']['relatedItemData']['includeContent']!r}"
    )

    # flip enabled off and confirm the change persists, not the stale value
    cc.put_case_event_configuration(
        domainId=domain_id,
        eventBridge={"enabled": False, "includedData": config["includedData"]},
    )
    got_after = cc.get_case_event_configuration(domainId=domain_id)["eventBridge"]
    assert got_after["enabled"] is False, f"expected enabled=False, got {got_after['enabled']!r}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _delete_domain(ctx, domain_id):
    cc = ctx.client("connectcases")
    for _ in range(5):
        try:
            cc.delete_domain(domainId=domain_id)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] != "ConflictException":
                raise
            time.sleep(3.0)
    cc.delete_domain(domainId=domain_id)


def _create_active_domain(ctx):
    cc = ctx.client("connectcases")
    name = ctx.unique_name("sim2real-cc-domain-")
    domain_id = cc.create_domain(name=name)["domainId"]
    ctx.on_cleanup(lambda: _delete_domain(ctx, domain_id))
    status = _poll_until(
        lambda: cc.get_domain(domainId=domain_id)["domainStatus"],
        lambda s: s != "CreationInProgress",
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert status == "Active", f"domain reached terminal status {status!r}, expected Active"
    return domain_id


def _create_field(ctx, domain_id, field_type, name_prefix="field"):
    cc = ctx.client("connectcases")
    name = ctx.unique_name(f"sim2real-cc-{name_prefix}-")
    field_id = cc.create_field(domainId=domain_id, name=name, type=field_type)["fieldId"]
    ctx.on_cleanup(lambda: cc.delete_field(domainId=domain_id, fieldId=field_id))
    return field_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
