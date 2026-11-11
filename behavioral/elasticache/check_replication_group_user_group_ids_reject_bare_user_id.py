"""replication-group-user-group-ids-reject-bare-user-id."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _fault_base(code):
    """Strip the modeled Fault/Exception suffix so error codes compare on their base."""
    for suffix in ("Exception", "Fault"):
        if code and code.endswith(suffix) and len(code) > len(suffix):
            return code[: -len(suffix)]
    return code

def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) if a ClientError was raised,
    else ("OK", None)."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    return "OK", None

def _assert_error(fn, expected, expected_message):
    """Assert fn() fails with `expected` (Fault/Exception-suffix normalized) and exactly
    `expected_message`; return the code."""
    code, message = _error(fn)
    assert code != "OK", f"expected {expected} but the call SUCCEEDED"
    assert _fault_base(code) == _fault_base(expected), f"expected {expected}, got {code}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    return code

def _delete_user_group_if_present(ec, group_id, timeout_s=180, interval_s=5):
    """Delete a user group, retrying while CreateUserGroup's own async settle (status
    'creating' -> 'active') is still in progress -- a group cannot be deleted until it is."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec.delete_user_group(UserGroupId=group_id)
            return
        except ClientError as e:
            code = _fault_base(e.response.get("Error", {}).get("Code") or "")
            if code == "UserGroupNotFound":
                return
            if code != "InvalidUserGroupState" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

def _delete_user_if_present(ec, user_id):
    try:
        ec.delete_user(UserId=user_id)
    except ClientError as e:
        if _fault_base(e.response.get("Error", {}).get("Code") or "") != "UserNotFound":
            raise

CHECK = "replication-group-user-group-ids-reject-bare-user-id"
GROUP = 'user-group'
SERVICES = ['elasticache']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateReplicationGroup rejects a real USER id in UserGroupIds with UserGroupNotFoundFault
    and creates nothing; the same request naming the user's group clears that validation and
    fails later on a nonexistent parameter group instead.
    """
    ec = ctx.client("elasticache")

    user_id = ctx.unique_name("sim2real-ecugb-u-")
    ec.create_user(
        UserId=user_id,
        UserName=user_id,
        Engine="redis",
        AccessString="on ~* +@all",
        Passwords=["Sim2RealBareUserProbe-2026xyz"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_user_if_present(ec, user_id))

    group_id = ctx.unique_name("sim2real-ecugb-g-")
    ec.create_user_group(
        UserGroupId=group_id,
        Engine="redis",
        UserIds=["default", user_id],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_user_group_if_present(ec, group_id))

    bad_rg_id = ctx.unique_name("sim2real-ecugb-rg-")
    # UserGroupIds names a real USER, not a user GROUP; the rejection is synchronous.
    subnet_group = _network_cache_subnet_group(ctx, ec)
    _assert_error(
        lambda: ec.create_replication_group(
            ReplicationGroupId=bad_rg_id,
            ReplicationGroupDescription="sim2real bare-user-id-as-group-id probe",
            Engine="redis",
            CacheNodeType="cache.t3.micro",
            NumCacheClusters=1,
            TransitEncryptionEnabled=True,
            UserGroupIds=[user_id],
            CacheSubnetGroupName=subnet_group,
        ),
        "UserGroupNotFoundFault",
        f"User group {user_id} not found.",
    )
    not_found_code, not_found_msg = _error(
        lambda: ec.describe_replication_groups(ReplicationGroupId=bad_rg_id)
    )
    assert not_found_code != "OK", (
        f"rejected create_replication_group(UserGroupIds=[{user_id!r}]) left a replication "
        f"group {bad_rg_id!r} behind"
    )
    assert _fault_base(not_found_code) == "ReplicationGroupNotFound", (
        f"expected ReplicationGroupNotFoundFault, got {not_found_code}"
    )
    expected = f"ReplicationGroup {bad_rg_id} not found."
    assert not_found_msg == expected, f"expected message {expected!r}, got {not_found_msg!r}"

    # Same request naming the user's own group: a deliberately nonexistent parameter group makes
    # it fail after UserGroupIds validation, so nothing is provisioned.
    good_rg_id = ctx.unique_name("sim2real-ecugb-rgg-")
    pg_name = ctx.unique_name("sim2real-ecugb-pg-")
    control_code, control_msg = _error(
        lambda: ec.create_replication_group(
            ReplicationGroupId=good_rg_id,
            ReplicationGroupDescription="sim2real real-group-id positive control",
            Engine="redis",
            CacheNodeType="cache.t3.micro",
            NumCacheClusters=1,
            TransitEncryptionEnabled=True,
            UserGroupIds=[group_id],
            CacheParameterGroupName=pg_name,
            CacheSubnetGroupName=subnet_group,
        )
    )
    assert control_code != "OK", (
        "positive control unexpectedly SUCCEEDED -- it was meant to fail later, on the "
        "nonexistent parameter group, not to actually provision a replication group"
    )
    assert _fault_base(control_code) == "CacheParameterGroupNotFound", (
        f"expected the real group id to clear UserGroupIds validation and fail with "
        f"CacheParameterGroupNotFoundFault instead, got {control_code} -- a UserGroupNotFound "
        f"here would mean the positive control did not actually exercise a different code path"
    )
    expected = f"CacheParameterGroup not found: {pg_name}"
    assert control_msg == expected, f"expected message {expected!r}, got {control_msg!r}"
    control_not_found, control_not_found_msg = _error(
        lambda: ec.describe_replication_groups(ReplicationGroupId=good_rg_id)
    )
    assert control_not_found != "OK", (
        f"positive-control create_replication_group left a replication group "
        f"{good_rg_id!r} behind despite failing on CacheParameterGroupNotFound"
    )
    assert _fault_base(control_not_found) == "ReplicationGroupNotFound", (
        f"expected ReplicationGroupNotFoundFault, got {control_not_found}"
    )
    expected = f"ReplicationGroup {good_rg_id} not found."
    assert control_not_found_msg == expected, (
        f"expected message {expected!r}, got {control_not_found_msg!r}"
    )


def _network_cache_subnet_group(ctx, client) -> str:
    """An ElastiCache subnet group over the shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-csg-")
    client.create_cache_subnet_group(
        CacheSubnetGroupName=name,
        CacheSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_cache_subnet_group(CacheSubnetGroupName=name),
            # DeleteCacheSubnetGroup refuses a group a cluster still holds with CacheSubnetGroupInUse.
            ("CacheSubnetGroupInUse", "InvalidCacheSubnetGroupState"),
            ("CacheSubnetGroupNotFoundFault",),
        )
    )
    return name


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=15.0):
    """Delete a subnet group, retrying while a resource that is being deleted still uses it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code not in busy_codes or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
