"""update-invoice-unit-fields-and-last-modified."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-invoice-unit-fields-and-last-modified"
GROUP = "e2e"
SERVICES = ["invoicing"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateInvoiceUnit applies Description and TaxInheritanceDisabled and advances
    LastModified; after delete Get fails with ResourceNotFoundException, and an AsOf
    listing still shows the unit."""
    import datetime

    invoicing = ctx.client("invoicing")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-iu-")

    t_before_create = datetime.datetime.now(datetime.timezone.utc)

    # AsOf history is compared at whole-second resolution; wait, bounded, until
    # the wall clock has crossed into a strictly later second than
    # t_before_create so a pre-creation AsOf query cannot land in the same
    # second as the create call and be treated as concurrent with it.
    _wait_past_second(t_before_create)

    # 1. Create
    arn = invoicing.create_invoice_unit(
        Name=name,
        InvoiceReceiver=account_id,
        Description="original description",
        Rule={"LinkedAccounts": [account_id], "BillSourceAccounts": []},
        ResourceTags=[{"Key": "sim2real-owner", "Value": "invoicing-suite"}],
    )["InvoiceUnitArn"]
    ctx.on_cleanup(lambda: _safe_delete_invoice_unit(ctx, arn))

    # 2. Get: fields match what was supplied.
    before = invoicing.get_invoice_unit(InvoiceUnitArn=arn)
    assert before["Description"] == "original description", (
        f"expected freshly created Description to be 'original description', got {before['Description']!r}"
    )
    assert before["TaxInheritanceDisabled"] is False, (
        f"expected default TaxInheritanceDisabled to be False, got {before['TaxInheritanceDisabled']!r}"
    )
    last_modified_before = before["LastModified"]

    # 3. Tag, then read tags back.
    invoicing.tag_resource(ResourceArn=arn, ResourceTags=[{"Key": "sim2real-stage", "Value": "created"}])
    tags = {t["Key"]: t["Value"] for t in invoicing.list_tags_for_resource(ResourceArn=arn)["ResourceTags"]}
    assert tags == {"sim2real-owner": "invoicing-suite", "sim2real-stage": "created"}, (
        f"expected both the creation-time and tag_resource-added tags, got {tags!r}"
    )

    # 4. List, filtered by name, sees the unit.
    listed = invoicing.list_invoice_units(Filters={"Names": [name]}, MaxResults=10)["InvoiceUnits"]
    assert any(u["InvoiceUnitArn"] == arn for u in listed), (
        f"expected {arn!r} in name-filtered listing, got {[u['InvoiceUnitArn'] for u in listed]!r}"
    )

    # LastModified carries whole-second resolution; wait, bounded, until the
    # wall clock has crossed into a strictly later second than the create's
    # own LastModified so the update below can be distinguished from it.
    _wait_past_second(last_modified_before)

    # 5. Update: Description/TaxInheritanceDisabled change, LastModified advances.
    invoicing.update_invoice_unit(
        InvoiceUnitArn=arn,
        Description="updated description",
        TaxInheritanceDisabled=True,
    )
    after = _poll_until(
        lambda: invoicing.get_invoice_unit(InvoiceUnitArn=arn),
        lambda got: got["Description"] == "updated description",
        timeout_s=30.0,
    )
    assert after["Description"] == "updated description", (
        f"expected Description to become 'updated description' after update, got {after['Description']!r}"
    )
    assert after["TaxInheritanceDisabled"] is True, (
        f"expected TaxInheritanceDisabled to become True after update, got {after['TaxInheritanceDisabled']!r}"
    )
    assert after["LastModified"] > last_modified_before, (
        f"expected LastModified to advance past {last_modified_before!r} after update, got {after['LastModified']!r}"
    )

    # 6. Untag, then confirm only the tag_resource-added key was removed.
    invoicing.untag_resource(ResourceArn=arn, ResourceTagKeys=["sim2real-stage"])
    remaining = {t["Key"]: t["Value"] for t in invoicing.list_tags_for_resource(ResourceArn=arn)["ResourceTags"]}
    assert remaining == {"sim2real-owner": "invoicing-suite"}, (
        f"expected only the persistent owner tag to remain after untagging 'sim2real-stage', got {remaining!r}"
    )

    # Use the server's own recorded LastModified (from the update above) as
    # the pre-delete snapshot instant -- that is authoritative ground truth
    # (the unit provably existed at that exact instant) and avoids any local
    # wall-clock/server-clock skew a locally-generated timestamp could hit.
    t_before_delete = after["LastModified"]

    # The update's own version must age past its own whole-second boundary
    # before the next mutation (delete), or a historical AsOf query pinned to
    # this instant can land in the same second as the delete and miss the unit.
    _wait_past_second(t_before_delete)

    # 7. Delete, then confirm the live Get is rejected.
    invoicing.delete_invoice_unit(InvoiceUnitArn=arn)
    del_err = _client_error(lambda: invoicing.get_invoice_unit(InvoiceUnitArn=arn))
    assert del_err["Code"] == "ResourceNotFoundException", (
        f"expected GetInvoiceUnit on a deleted ARN to raise ResourceNotFoundException, got {del_err['Code']!r}"
    )
    assert del_err["Message"] == "The resource could not be found.", (
        f"expected message 'The resource could not be found.', got {del_err['Message']!r}"
    )

    # 8. As-of history: before creation the unit didn't exist yet.
    before_create_listing = invoicing.list_invoice_units(
        Filters={"Names": [name]}, AsOf=t_before_create, MaxResults=10
    )["InvoiceUnits"]
    assert not any(u["InvoiceUnitArn"] == arn for u in before_create_listing), (
        f"expected {arn!r} absent from a pre-creation AsOf listing, got "
        f"{[u['InvoiceUnitArn'] for u in before_create_listing]!r}"
    )

    # 9. As-of history: between creation and deletion, it existed.
    mid_lifetime_listing = invoicing.list_invoice_units(
        Filters={"Names": [name]}, AsOf=t_before_delete, MaxResults=10
    )["InvoiceUnits"]
    assert any(u["InvoiceUnitArn"] == arn for u in mid_lifetime_listing), (
        "a historical AsOf view between create and delete must still show the unit"
    )


def _wait_past_second(moment, *, timeout_s=5.0, interval_s=0.1):
    """Block, bounded, until the wall clock has crossed into a whole second
    strictly later than `moment` (a tz-aware datetime)."""
    import datetime

    deadline = time.monotonic() + timeout_s
    target_second = int(moment.timestamp())
    while int(datetime.datetime.now(datetime.timezone.utc).timestamp()) <= target_second:
        if time.monotonic() >= deadline:
            raise AssertionError(f"wall clock did not cross into a later second than {moment!r} within {timeout_s}s")
        time.sleep(interval_s)


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because a
    target accepting input real AWS refuses must not read as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe_delete_invoice_unit(ctx, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        ctx.client("invoicing").delete_invoice_unit(InvoiceUnitArn=arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.5):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

