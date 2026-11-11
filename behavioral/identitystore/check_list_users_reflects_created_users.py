"""list-users-reflects-created-users."""
from __future__ import annotations

import time as _time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-users-reflects-created-users"
GROUP = "data-plane"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """A freshly created user is discoverable via ListUsers (paginated) with its UserName intact."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")

    username = ctx.unique_name("sim2real-user-")
    user_id = idstore.create_user(
        IdentityStoreId=store_id,
        UserName=username,
        DisplayName=username,
        Name={"GivenName": "List", "FamilyName": "Reflects"},
    )["UserId"]
    ctx.on_cleanup(_teardown(
        lambda: idstore.delete_user(IdentityStoreId=store_id, UserId=user_id), "ResourceNotFoundException",
    ))

    found = None
    next_token = None
    for _ in range(200):
        kwargs = {"IdentityStoreId": store_id, "MaxResults": 100}
        if next_token:
            kwargs["NextToken"] = next_token
        page = idstore.list_users(**kwargs)
        for u in page["Users"]:
            if u["UserId"] == user_id:
                found = u
                break
        if found:
            break
        next_token = page.get("NextToken")
        if not next_token:
            break

    assert found is not None, "created user not found via ListUsers"
    assert found["UserName"] == username, f"expected UserName {username!r}, got {found['UserName']!r}"


def _teardown(undo, *not_found: str):
    """``undo()`` where a failed delete raises; only ``not_found`` codes mean it is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _get_identity_store_id(ctx):
    ssoadmin = ctx.client("sso-admin")
    try:
        resp = ssoadmin.list_instances()
    except Exception as exc:
        raise AssertionError(
            f"ssoadmin.list_instances is unavailable ({exc}); identitystore has no API of its "
            "own to provision an identity store, so a pre-existing (or emulator-seeded) IAM "
            "Identity Center instance is required"
        ) from exc
    instances = resp.get("Instances", [])
    if instances:
        return instances[0]["IdentityStoreId"]
    try:
        created = ssoadmin.create_instance(Name=ctx.unique_name("sim2real-idc-"))
    except Exception as exc:
        raise AssertionError(
            f"no IAM Identity Center instance exists and ssoadmin.create_instance failed ({exc}); "
            "this is expected for AWS Organizations management/member accounts, which reject "
            "self-service instance creation -- run against a standalone account or an emulator "
            "that seeds a default identity store"
        ) from exc
    instance_arn = created["InstanceArn"]
    ctx.on_cleanup(_teardown(
        lambda: ssoadmin.delete_instance(InstanceArn=instance_arn), "ResourceNotFoundException",
    ))
    deadline = _time.monotonic() + 30
    while _time.monotonic() < deadline:
        resp = ssoadmin.list_instances()
        for inst in resp.get("Instances", []):
            if inst.get("InstanceArn") == instance_arn and inst.get("IdentityStoreId"):
                return inst["IdentityStoreId"]
        _time.sleep(1)
    raise AssertionError(
        "created an IAM Identity Center instance but its IdentityStoreId never appeared via "
        "list_instances within 30s",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
