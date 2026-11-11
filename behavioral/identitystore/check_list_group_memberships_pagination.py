"""list-group-memberships-pagination."""
from __future__ import annotations

import time as _time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-group-memberships-pagination"
GROUP = "data-plane"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """ListGroupMemberships with MaxResults=1 pages through NextToken and the union of all
    pages exactly matches every membership created for the group (no loss, no duplication)."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")

    group_id = idstore.create_group(
        IdentityStoreId=store_id, DisplayName=ctx.unique_name("sim2real-group-")
    )["GroupId"]
    ctx.on_cleanup(_teardown(lambda: idstore.delete_group(IdentityStoreId=store_id, GroupId=group_id),
                              "ResourceNotFoundException"))

    expected_user_ids = set()
    for _ in range(3):
        user_id = idstore.create_user(
            IdentityStoreId=store_id,
            UserName=ctx.unique_name("sim2real-user-"),
            DisplayName=ctx.unique_name("sim2real-user-"),
            Name={"GivenName": "Page", "FamilyName": "Membership"},
        )["UserId"]
        ctx.on_cleanup(_teardown(lambda uid=user_id: idstore.delete_user(IdentityStoreId=store_id, UserId=uid),
                                  "ResourceNotFoundException"))
        idstore.create_group_membership(
            IdentityStoreId=store_id, GroupId=group_id, MemberId={"UserId": user_id}
        )
        expected_user_ids.add(user_id)

    seen_user_ids = []
    next_token = None
    for _ in range(20):
        kwargs = {"IdentityStoreId": store_id, "GroupId": group_id, "MaxResults": 1}
        if next_token:
            kwargs["NextToken"] = next_token
        page = idstore.list_group_memberships(**kwargs)
        assert len(page["GroupMemberships"]) <= 1, page["GroupMemberships"]
        for m in page["GroupMemberships"]:
            seen_user_ids.append(m["MemberId"]["UserId"])
        next_token = page.get("NextToken")
        if not next_token:
            break

    assert len(seen_user_ids) == len(expected_user_ids), seen_user_ids
    assert set(seen_user_ids) == expected_user_ids


def _teardown(undo, *not_found: str):
    """Run undo(), returning only on the resource's own not_found codes and raising the rest."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


#: An Identity Center instance lists its IdentityStoreId once it is ACTIVE.
INSTANCE_READY_TIMEOUT_S = 180.0


def _get_identity_store_id(ctx):
    ssoadmin = ctx.client("sso-admin")
    try:
        instances = ssoadmin.list_instances().get("Instances", [])
    except Exception as exc:
        raise AssertionError(
            f"ssoadmin.list_instances is unavailable ({exc}); identitystore has no API of its "
            "own to provision an identity store, so a pre-existing (or emulator-seeded) IAM "
            "Identity Center instance is required"
        ) from exc
    if not instances:
        try:
            created = ssoadmin.create_instance(Name=ctx.unique_name("sim2real-idc-"))
        except Exception as exc:
            raise AssertionError(
                f"no IAM Identity Center instance exists and ssoadmin.create_instance failed "
                f"({exc}); this is expected for AWS Organizations management/member accounts, "
                "which reject self-service instance creation -- run against a standalone account "
                "or an emulator that seeds a default identity store"
            ) from exc
        instance_arn = created["InstanceArn"]
        ctx.on_cleanup(
            _teardown(
                lambda: ssoadmin.delete_instance(InstanceArn=instance_arn),
                "ResourceNotFoundException",
            )
        )
    # An instance still being created lists no IdentityStoreId yet: poll until one does.
    start = _time.monotonic()
    left = ctx.time_left()
    cap_s = INSTANCE_READY_TIMEOUT_S
    if left is not None:
        cap_s = max(1.0, min(cap_s, left - 5.0))
    while True:
        ready = [i["IdentityStoreId"] for i in instances if i.get("IdentityStoreId")]
        if ready:
            return ready[0]
        if _time.monotonic() - start >= cap_s:
            if cap_s < INSTANCE_READY_TIMEOUT_S:
                raise TimeoutError(
                    f"the check's time budget ran out after {_time.monotonic() - start:.1f}s, "
                    f"before the {INSTANCE_READY_TIMEOUT_S:.0f}s wait for an IdentityStoreId "
                    "ended; not graded"
                )
            raise AssertionError(
                f"no IAM Identity Center instance listed an IdentityStoreId within "
                f"{INSTANCE_READY_TIMEOUT_S:.0f}s; last ListInstances {instances!r}"
            )
        _time.sleep(2.0)
        instances = ssoadmin.list_instances().get("Instances", [])

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
