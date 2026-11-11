"""field-option-batch-put-and-list-round-trip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "field-option-batch-put-and-list-round-trip"
GROUP = "data-plane"
SERVICES = ["connectcases"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchPutFieldOptions writes options for a SingleSelect field and ListFieldOptions
    returns those exact options, including the active/inactive flag distinction."""
    cc = ctx.client("connectcases")
    domain_id = _create_active_domain(ctx)
    select_field = _create_field(ctx, domain_id, "SingleSelect", "select")

    resp = cc.batch_put_field_options(
        domainId=domain_id,
        fieldId=select_field,
        options=[
            {"name": "Low", "value": "low", "active": True},
            {"name": "High", "value": "high", "active": False},
        ],
    )
    assert resp["errors"] == [], f"unexpected per-option errors: {resp['errors']}"

    options = cc.list_field_options(domainId=domain_id, fieldId=select_field)["options"]
    by_value = {o["value"]: o for o in options}
    assert by_value["low"]["name"] == "Low", f"expected name 'Low' for value 'low', got {by_value['low']}"
    assert by_value["low"]["active"] is True, f"expected 'low' active=True, got {by_value['low']}"
    assert by_value["high"]["name"] == "High", f"expected name 'High' for value 'high', got {by_value['high']}"
    assert by_value["high"]["active"] is False, f"expected 'high' active=False, got {by_value['high']}"


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
