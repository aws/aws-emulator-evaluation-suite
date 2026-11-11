"""batch-put-profile-object-partial-failure."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-put-profile-object-partial-failure"
GROUP = "data-plane"
SERVICES = ["customer-profiles"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchPutProfileObject partitions a mixed batch: the well-formed item succeeds and is
    independently readable via ListProfileObjects at the destination profile; the malformed one is
    reported Failed and never persists anywhere."""
    cp = ctx.client("customer-profiles")
    domain = ctx.unique_name("sim2real-cp-dom-")
    object_type = "Events"
    account_number = ctx.unique_name("sim2real-acct-")
    event_id = ctx.unique_name("sim2real-evt-")

    cp.create_domain(DomainName=domain, DefaultExpirationDays=30, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: cp.delete_domain(DomainName=domain)))

    cp.put_profile_object_type(
        DomainName=domain,
        ObjectTypeName=object_type,
        Description="events",
        AllowProfileCreation=True,
        Fields={
            "account_id": {"ContentType": "STRING", "Source": "_source.account_id", "Target": "_profile.AccountNumber"},
            "payload": {"ContentType": "STRING", "Source": "_source.payload", "Target": "_profile.Attributes.payload"},
            "event_id": {"ContentType": "STRING", "Source": "_source.event_id", "Target": "_profile.Attributes.event_id"},
        },
        Keys={"eventKey": [{"StandardIdentifiers": ["PROFILE", "UNIQUE"], "FieldNames": ["event_id"]}]},
    )
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: cp.delete_profile_object_type(DomainName=domain, ObjectTypeName=object_type)
        )
    )

    resp = cp.batch_put_profile_object(
        DomainName=domain,
        ObjectTypeName=object_type,
        Items=[
            {"Id": "good-1", "Object": json.dumps({"account_id": account_number, "payload": "ok", "event_id": event_id})},
            {"Id": "bad-1", "Object": "{this is not valid json"},
        ],
    )

    successful = {i["Id"]: i for i in resp.get("Successful", [])}
    failed_ids = {i["Id"] for i in resp.get("Failed", [])}
    assert set(successful) == {"good-1"}, f"expected only good-1 in Successful, got {set(successful)}"
    assert failed_ids == {"bad-1"}, f"expected only bad-1 in Failed, got {failed_ids}"
    good_unique_key = successful["good-1"]["ProfileObjectUniqueKey"]

    search = _poll_until(
        lambda: cp.search_profiles(DomainName=domain, KeyName="_account", Values=[account_number]),
        lambda r: len(r.get("Items", [])) > 0,
        timeout_s=60,
    )
    profile_id = search["Items"][0]["ProfileId"]

    listed = _poll_until(
        lambda: cp.list_profile_objects(DomainName=domain, ObjectTypeName=object_type, ProfileId=profile_id),
        lambda r: len(r.get("Items", [])) > 0,
        timeout_s=60,
    )
    items = listed["Items"]
    matching = [i for i in items if i["ProfileObjectUniqueKey"] == good_unique_key]
    assert len(matching) == 1, f"expected exactly one persisted object for good-1, got {items}"
    assert json.loads(matching[0]["Object"])["payload"] == "ok", f"persisted payload mismatch: {matching[0]}"
    assert len(items) == 1, f"expected bad-1 to leave no persisted object at the destination, got {items}"


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
