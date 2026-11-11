"""create-order-then-cancel-transitions-to-cancelled."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-order-then-cancel-transitions-to-cancelled"
GROUP = "orders"
SERVICES = ["outposts"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateOrder for a new Outpost on a site without qualified details fails with ValidationException and the
    message "The site details are incomplete. Reach out to AWS Support for assistance.", and ListOrders shows no
    order for the Outpost; an accepted order is cancelled at once and fails the check.
    """
    outposts = ctx.client("outposts")

    page = outposts.list_catalog_items(MaxResults=10)
    items = [i for i in page.get("CatalogItems", []) if i.get("ItemStatus") == "AVAILABLE"]
    if not items:
        raise AssertionError(
            "no AVAILABLE catalog items visible to this account/region; the positive control "
            "for this check needs at least one orderable CatalogItemId to prove Outposts "
            "itself is reachable before CreateOrder's refusal means anything."
        )

    site_id = outposts.create_site(
        Name=ctx.unique_name("sim2real-outposts-site-"),
        Tags={"sim2real-check": CHECK},
    )["Site"]["SiteId"]
    ctx.on_cleanup(lambda: outposts.delete_site(SiteId=site_id))
    outpost_id = outposts.create_outpost(
        Name=ctx.unique_name("sim2real-outposts-op-"),
        SiteId=site_id,
        AvailabilityZone=_pick_availability_zone(ctx),
        Tags={"sim2real-check": CHECK},
    )["Outpost"]["OutpostId"]
    ctx.on_cleanup(lambda: outposts.delete_outpost(OutpostId=outpost_id))

    # Positive control: ListCatalogItems returning AVAILABLE items plus CreateSite/CreateOutpost
    # succeeding above already prove the account and credentials are healthy for Outposts, so a
    # CreateOrder refusal below cannot be "nothing here works" -- only ordering itself is gated.
    item = min(items, key=_item_size)
    try:
        order = outposts.create_order(
            OutpostIdentifier=outpost_id,
            LineItems=[{"CatalogItemId": item["CatalogItemId"], "Quantity": 1}],
            PaymentOption="NO_UPFRONT",
        )["Order"]
    except ClientError as err:
        code = err.response["Error"]["Code"]
        message = err.response["Error"].get("Message") or ""
        assert code == "ValidationException", (
            f"expected CreateOrder to be refused with ValidationException, got {code} ({message!r})"
        )
        assert message == "The site details are incomplete. Reach out to AWS Support for assistance.", (
            f"expected the refusal to cite incomplete site details, got Message={message!r}"
        )
        orders = outposts.list_orders(OutpostIdentifierFilter=outpost_id)["Orders"]
        assert orders == [], f"expected no Order for {outpost_id!r} after the refusal, got {orders!r}"
        return

    # CreateOrder succeeding here means the account's Outposts entitlement differs from the
    # refusal asserted above. Cancel the real hardware order immediately -- do not leave it
    # standing on a multi-year term -- and fail loudly so the order-then-cancel path is
    # asserted for real.
    order_id = order["OrderId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: outposts.cancel_order(OrderId=order_id)))
    outposts.cancel_order(OrderId=order_id)
    raise AssertionError(
        f"CreateOrder unexpectedly SUCCEEDED (OrderId={order_id!r}, OutpostId={outpost_id!r}); "
        "this account now has real Outposts ordering entitlement, so this check's "
        "refusal-shaped contract is stale. The order was cancelled immediately; this check "
        "needs rewriting to exercise the real place-then-cancel status transition its "
        "CHECK id and filename name."
    )


def _item_size(item) -> tuple:
    """Order catalog items smallest-first. ListCatalogItems carries no price, so this uses the
    physical/capacity members as a proxy: PowerKva, WeightLbs, then summed EC2 instance slots."""
    ec2_slots = sum(_as_int(c.get("Quantity")) for c in item.get("EC2Capacities") or [])
    return (
        float(item.get("PowerKva") or 0.0),
        float(item.get("WeightLbs") or 0.0),
        ec2_slots,
    )


def _as_int(value) -> int:
    """EC2Capacity.Quantity is modelled as a string; tolerate anything non-numeric."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _best_effort(fn) -> None:
    """Run a teardown call, accepting only NotFoundException."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _pick_availability_zone(ctx) -> str:
    ec2 = ctx.client("ec2")
    zones = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    assert zones, "no available Availability Zones found in this region"
    return zones[0]["ZoneName"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
