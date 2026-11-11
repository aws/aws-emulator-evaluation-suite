"""put-profile-object-list-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-profile-object-list-and-delete"
GROUP = "data-plane"
SERVICES = ["customer-profiles"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutProfileObject with AllowProfileCreation infers a new profile; ListProfileObjects shows it; DeleteProfileObject removes it."""
    cp = ctx.client("customer-profiles")
    domain = ctx.unique_name("sim2real-cp-dom-")
    object_type = "Orders"
    account_number = ctx.unique_name("sim2real-acct-")
    order_id = ctx.unique_name("sim2real-ord-")

    cp.create_domain(
        DomainName=domain,
        DefaultExpirationDays=30,
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: cp.delete_domain(DomainName=domain)))

    cp.put_profile_object_type(
        DomainName=domain,
        ObjectTypeName=object_type,
        Description="orders",
        AllowProfileCreation=True,
        Fields={
            "account_id": {"Source": "_source.account_id", "Target": "_profile.AccountNumber", "ContentType": "STRING"},
            "order_id": {"Source": "_source.order_id", "Target": "_profile.Attributes.order_id", "ContentType": "STRING"},
        },
        Keys={"orderKey": [{"StandardIdentifiers": ["PROFILE", "UNIQUE"], "FieldNames": ["order_id"]}]},
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: cp.delete_profile_object_type(DomainName=domain, ObjectTypeName=object_type)
        )
    )

    put_resp = cp.put_profile_object(
        DomainName=domain,
        ObjectTypeName=object_type,
        Object=json.dumps({"account_id": account_number, "order_id": order_id}),
    )
    unique_key = put_resp["ProfileObjectUniqueKey"]

    search = _poll_until(
        lambda: cp.search_profiles(DomainName=domain, KeyName="_account", Values=[account_number]),
        lambda r: len(r.get("Items", [])) > 0,
        timeout_s=60,
    )
    profile_id = search["Items"][0]["ProfileId"]

    listed = _poll_until(
        lambda: cp.list_profile_objects(
            DomainName=domain, ObjectTypeName=object_type, ProfileId=profile_id
        ),
        lambda r: len(r.get("Items", [])) > 0,
        timeout_s=60,
    )
    matching = [i for i in listed["Items"] if i["ProfileObjectUniqueKey"] == unique_key]
    assert len(matching) == 1, f"expected exactly one object with key {unique_key!r}, found {len(matching)}"
    got_order_id = json.loads(matching[0]["Object"])["order_id"]
    assert got_order_id == order_id, f"expected order_id={order_id!r}, got {got_order_id!r}"

    cp.delete_profile_object(
        DomainName=domain,
        ProfileId=profile_id,
        ProfileObjectUniqueKey=unique_key,
        ObjectTypeName=object_type,
    )
    _poll_until(
        lambda: cp.list_profile_objects(
            DomainName=domain, ObjectTypeName=object_type, ProfileId=profile_id
        ),
        lambda r: len(r.get("Items", [])) == 0,
        timeout_s=60,
    )

    # A fresh, independent call after the poll succeeds — not the memoized poll
    # result, whose own predicate already guaranteed the value and so could
    # never fail here.
    confirmed = cp.list_profile_objects(
        DomainName=domain, ObjectTypeName=object_type, ProfileId=profile_id
    )
    assert confirmed.get("Items", []) == [], f"expected no objects after delete, got {confirmed.get('Items')!r}"


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
