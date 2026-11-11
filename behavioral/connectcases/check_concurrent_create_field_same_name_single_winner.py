"""concurrent-create-field-same-name-single-winner."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-field-same-name-single-winner"
GROUP = "concurrency"
SERVICES = ["connectcases"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """When several CreateField calls race with the exact same name in the same domain,
    exactly one succeeds and the rest fail with ConflictException; ListFields ends up
    with exactly one field for that name, not zero and not several."""
    cc = ctx.client("connectcases")
    domain_id = _create_active_domain(ctx)
    name = ctx.unique_name("sim2real-cc-race-field-")

    def _attempt(_i):
        try:
            field_id = cc.create_field(domainId=domain_id, name=name, type="Text")["fieldId"]
            return ("ok", field_id)
        except ClientError as err:
            return ("err", (err.response["Error"]["Code"], err.response["Error"].get("Message")))

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(_attempt, range(8)))

    winners = [r for kind, r in results if kind == "ok"]
    losers = [r for kind, r in results if kind == "err"]

    assert len(winners) == 1, f"expected exactly one winner, got {len(winners)}: {results}"
    assert len(losers) == 7, f"expected exactly seven losers, got {len(losers)}: {results}"
    assert all(code == "ConflictException" for code, _ in losers), f"unexpected loser codes: {losers}"
    expected_conflict = f"Field creation failed: field resource with the name {name} already exists!"
    assert all(message == expected_conflict for _, message in losers), (
        f"expected every loser message to be {expected_conflict!r}, got {losers}"
    )

    winning_field_id = winners[0]
    ctx.on_cleanup(lambda: _delete_field_if_present(cc, domain_id, winning_field_id))

    fields = cc.list_fields(domainId=domain_id)["fields"]
    matching = [f for f in fields if f["name"] == name]
    assert len(matching) == 1, f"expected exactly one field named {name!r}, got {matching}"
    assert matching[0]["fieldId"] == winning_field_id, (
        f"listed field {matching[0]['fieldId']!r} does not match winning field {winning_field_id!r}"
    )

    cc.delete_field(domainId=domain_id, fieldId=winning_field_id)

    fields_after_delete = cc.list_fields(domainId=domain_id)["fields"]
    assert not any(f["fieldId"] == winning_field_id for f in fields_after_delete), (
        f"deleted field {winning_field_id} still present in list_fields: {fields_after_delete}"
    )

    try:
        cc.update_field(domainId=domain_id, fieldId=winning_field_id, description="post-delete-update")
        raise AssertionError(f"expected ResourceNotFoundException updating deleted field {winning_field_id}")
    except ClientError as err:
        code = err.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException updating deleted field, got {code}"
        )
        message = err.response["Error"].get("Message")
        assert message == "Requested resource not found.", (
            f"expected message 'Requested resource not found.' updating deleted field, got {message!r}"
        )


def _delete_field_if_present(cc, domain_id, field_id):
    try:
        cc.delete_field(domainId=domain_id, fieldId=field_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
