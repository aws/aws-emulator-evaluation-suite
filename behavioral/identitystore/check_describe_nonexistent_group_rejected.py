"""describe-nonexistent-group-rejected."""
from __future__ import annotations

import time as _time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "describe-nonexistent-group-rejected"
GROUP = "overly-permissive"
SERVICES = ["identitystore"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """DescribeGroup for a syntactically valid but never-created GroupId is rejected with
    ResourceNotFoundException, while a positive control describing a real group in the same
    store succeeds."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")

    bogus_group_id = str(uuid.uuid4())
    code, message = _client_error(
        lambda: idstore.describe_group(IdentityStoreId=store_id, GroupId=bogus_group_id)
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException describing a never-created GroupId, got {code!r}"
    )
    assert message == "Group not found", (
        f"expected AWS's exact ResourceNotFoundException message, got {message!r}"
    )

    # positive control: a real group in the same store describes fine
    real_group_id = idstore.create_group(
        IdentityStoreId=store_id, DisplayName=ctx.unique_name("sim2real-group-")
    )["GroupId"]
    ctx.on_cleanup(lambda: _safe(lambda: idstore.delete_group(IdentityStoreId=store_id, GroupId=real_group_id)))
    described = idstore.describe_group(IdentityStoreId=store_id, GroupId=real_group_id)
    assert described["GroupId"] == real_group_id, (
        f"expected DescribeGroup to echo back {real_group_id!r} for the just-created group, "
        f"got {described.get('GroupId')!r}"
    )


def _client_error(fn):
    """Run ``fn`` and return the (code, message) of the ClientError it raises; a success fails."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
    ctx.on_cleanup(lambda: _safe(lambda: ssoadmin.delete_instance(InstanceArn=instance_arn)))
    deadline = _time.monotonic() + 30
    while _time.monotonic() < deadline:
        resp = ssoadmin.list_instances()
        for inst in resp.get("Instances", []):
            if inst.get("InstanceArn") == instance_arn:
                store_id = inst.get("IdentityStoreId")
                if store_id:
                    return store_id
                break  # matched by ARN but IdentityStoreId has not propagated yet; keep polling
        _time.sleep(1)
    raise AssertionError(
        "created an IAM Identity Center instance but its IdentityStoreId never appeared via "
        "list_instances within 30s",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
