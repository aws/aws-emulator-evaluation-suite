"""batch-get-field-partial-errors."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-get-field-partial-errors"
GROUP = "data-plane"
SERVICES = ["connectcases"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchGetField partially succeeds: a valid field ID comes back in `fields` while a
    bogus one is reported in `errors` with errorCode "ResourceNotFound", in the same call."""
    cc = ctx.client("connectcases")
    domain_id = _create_active_domain(ctx)
    valid_field = _create_field(ctx, domain_id, "Text", "valid")
    bogus_field = "sim2real-nonexistent-field-id-0000000000"

    resp = cc.batch_get_field(domainId=domain_id, fields=[{"id": valid_field}, {"id": bogus_field}])

    assert len(resp["fields"]) == 1, f"expected exactly one resolved field, got {resp['fields']}"
    assert resp["fields"][0]["fieldId"] == valid_field, (
        f"expected resolved field {valid_field!r}, got {resp['fields'][0]['fieldId']!r}"
    )

    assert len(resp["errors"]) == 1, f"expected exactly one field error, got {resp['errors']}"
    assert resp["errors"][0]["id"] == bogus_field, (
        f"expected error entry for {bogus_field!r}, got {resp['errors'][0]['id']!r}"
    )
    assert resp["errors"][0]["errorCode"] == "ResourceNotFound", (
        f"expected ResourceNotFound for bogus field, got {resp['errors'][0]['errorCode']!r}"
    )


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
