"""put-inventory-custom-schema-limit-exceeded-rejected."""
from __future__ import annotations

import datetime
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-inventory-custom-schema-limit-exceeded-rejected"
GROUP = "overly-permissive"
SERVICES = ["ssm"]

_ACCOUNT_CUSTOM_SCHEMA_LIMIT = 20


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:ssm-custom-inventory-schemas")
def run(ctx) -> None:
    """PutInventory with a 21st custom inventory type fails with CustomSchemaCountLimitExceeded
    and creates nothing; deleting one schema lets the identical call succeed.
    """

    ssm = ctx.client("ssm")

    instance_id = _provision_ssm_managed_instance(ctx)

    existing_custom_types = _existing_custom_types(ssm)
    remaining = max(0, _ACCOUNT_CUSTOM_SCHEMA_LIMIT - len(existing_custom_types))

    new_types = [
        f"Custom:{ctx.unique_name('sim2realInvSch')}" for _ in range(remaining)
    ]
    for type_name in new_types:
        ctx.on_cleanup(_cleanup_schema(ssm, type_name))

    if new_types:
        ssm.put_inventory(
            InstanceId=instance_id, Items=[_item(t) for t in new_types]
        )

    # GetInventorySchema is eventually consistent with a just-completed PutInventory.
    at_cap = _poll_until(
        lambda: _existing_custom_types(ssm),
        lambda types: len(types) >= _ACCOUNT_CUSTOM_SCHEMA_LIMIT,
        timeout_s=_budget_s(ctx, 60.0),
        interval_s=2,
        ctx=ctx,
    )
    assert len(at_cap) == _ACCOUNT_CUSTOM_SCHEMA_LIMIT, (
        f"expected exactly {_ACCOUNT_CUSTOM_SCHEMA_LIMIT} custom types registered ("
        f"{len(existing_custom_types)} pre-existing + {len(new_types)} created by this check) "
        f"before testing the boundary, but GetInventorySchema now reports {len(at_cap)}: {at_cap}"
    )

    # Cleanup is registered before the call so an unexpected success is still torn down.
    extra_type = f"Custom:{ctx.unique_name('sim2realInvSchExtra')}"
    ctx.on_cleanup(_cleanup_schema(ssm, extra_type))
    code, message = _error_code(
        lambda: ssm.put_inventory(InstanceId=instance_id, Items=[_item(extra_type)])
    )
    assert code == "CustomSchemaCountLimitExceededException", (
        f"unexpected code: {code}; account reported {len(at_cap)} custom types "
        f"(limit {_ACCOUNT_CUSTOM_SCHEMA_LIMIT}) just before this call"
    )
    assert message == (
        f"Total custom inventory schema count exceeded the limit {_ACCOUNT_CUSTOM_SCHEMA_LIMIT}."
    ), message

    # Effect absent: the extra schema was never created.
    entries_code, entries_message = _error_code(
        lambda: ssm.list_inventory_entries(InstanceId=instance_id, TypeName=extra_type)
    )
    assert entries_code == "InvalidTypeNameException", f"unexpected code: {entries_code}"
    assert entries_message == f"Inventory type name {extra_type} is not defined.", entries_message

    # Writing under an already-registered custom type still succeeds at the cap.
    existing_type = new_types[0] if new_types else existing_custom_types[0]
    ssm.put_inventory(InstanceId=instance_id, Items=[_item(existing_type)])

    # Free a slot this check holds (never a schema it did not create).
    if new_types:
        freed_type = new_types[-1]
        deletion_id = ssm.delete_inventory(
            TypeName=freed_type, SchemaDeleteOption="DeleteSchema"
        )["DeletionId"]
        deletions = _poll_until(
            lambda: ssm.describe_inventory_deletions(DeletionId=deletion_id).get(
                "InventoryDeletions", []
            ),
            lambda ds: bool(ds) and ds[0].get("LastStatus") == "Complete",
            timeout_s=_budget_s(ctx, 600.0),
            interval_s=2,
            ctx=ctx,
        )
        assert deletions[0]["LastStatus"] == "Complete", (
            f"expected the freed schema's deletion to complete, got {deletions[0]!r}"
        )

        try:
            ssm.put_inventory(InstanceId=instance_id, Items=[_item(extra_type)])
        except ClientError as exc:
            raise AssertionError(
                f"freeing one custom-schema slot should let the identical PutInventory that was "
                f"just rejected succeed; got error code {exc.response['Error']['Code']!r}"
            ) from exc

        # The new type's schema is registered a little after the PutInventory that creates it;
        # until then ListInventoryEntries answers InvalidTypeNameException, and its entries
        # list a little after that.
        restored_entries = _poll_until(
            lambda: _entries_or_none(ssm, instance_id, extra_type),
            lambda r: r is not None and bool(r.get("Entries")),
            timeout_s=_budget_s(ctx, 180.0),
            interval_s=2,
            ctx=ctx,
        )
        assert restored_entries["Entries"], (
            f"expected {extra_type} to be listable now that it registered successfully"
        )


def _item(type_name: str) -> dict:
    return {
        "TypeName": type_name,
        "SchemaVersion": "1.0",
        "CaptureTime": datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "Content": [{"Attribute": "Value"}],
    }


def _existing_custom_types(ssm) -> list:
    types: list = []
    kwargs: dict = {}
    while True:
        resp = ssm.get_inventory_schema(**kwargs)
        for schema in resp.get("Schemas", []):
            if schema["TypeName"].startswith("Custom:"):
                types.append(schema["TypeName"])
        token = resp.get("NextToken")
        if not token:
            break
        kwargs["NextToken"] = token
    return types


def _error_code(fn):
    """(code, message) of the ClientError fn raises; a success fails the check."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _entries_or_none(ssm, instance_id: str, type_name: str):
    try:
        return ssm.list_inventory_entries(InstanceId=instance_id, TypeName=type_name)
    except ssm.exceptions.InvalidTypeNameException:
        return None


def _cleanup_schema(ssm, type_name: str) -> Callable[[], None]:
    def _cleanup() -> None:
        # An account runs at most 10 inventory deletions at once ("The total concurrent deletions
        # exceeds limit of 10"), and this check deletes up to 21 schemas; a refused delete waits
        # for earlier ones to finish and is issued again.
        deadline = time.monotonic() + 600.0
        while True:
            try:
                ssm.delete_inventory(TypeName=type_name, SchemaDeleteOption="DeleteSchema")
                return
            except ssm.exceptions.InvalidTypeNameException:
                return  # already deleted by the in-check restore leg
            except ssm.exceptions.InvalidInventoryRequestException as e:
                if "concurrent deletions" not in str(e) or time.monotonic() >= deadline:
                    raise
            time.sleep(2.0)

    return _cleanup


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float,
    interval_s: float,
    ctx=None,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("the polled condition: the run budget ended first; not graded")
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_running(ec2, instance_ids, timeout_s: float, ctx=None) -> None:
    """Poll every 2 s until every instance is running; fails on a dead-end state or the deadline."""
    deadline = time.monotonic() + timeout_s
    states = {}
    while True:
        try:
            reservations = ec2.describe_instances(InstanceIds=list(instance_ids))["Reservations"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidInstanceID.NotFound":
                raise
            reservations = []
        states = {i["InstanceId"]: i["State"]["Name"] for r in reservations for i in r["Instances"]}
        if len(states) == len(instance_ids) and all(s == "running" for s in states.values()):
            return
        assert not any(s in ("shutting-down", "terminated", "stopping", "stopped") for s in states.values()), (
            f"instances {list(instance_ids)} reached {states!r} instead of running")
        if time.monotonic() >= deadline and ctx is not None and _budget_spent(ctx):
            raise TimeoutError("instances reaching running: the run budget ended first; not graded")
        assert time.monotonic() < deadline, (
            f"instances {list(instance_ids)} not running in time: {states!r}")
        time.sleep(2.0)


def _provision_ssm_managed_instance(ctx) -> str:
    """Launch a minimal EC2 instance with an SSM instance profile and wait for it to
    register with SSM as an Online managed node."""
    iam = ctx.client("iam")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    subnet_id = ctx.network().subnet_ids[0]

    role_name = ctx.unique_name("sim2real-ssm-role-")
    profile_name = ctx.unique_name("sim2real-ssm-profile-")
    trust_policy = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        '"Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
    )
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
    policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(
        lambda: _safe(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    )
    iam.create_instance_profile(InstanceProfileName=profile_name)
    ctx.on_cleanup(
        lambda: _safe(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    )
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: _safe(
            lambda: iam.remove_role_from_instance_profile(
                InstanceProfileName=profile_name, RoleName=role_name
            )
        )
    )

    ami_id = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
    )["Parameter"]["Value"]

    instance_id = None
    deadline = time.monotonic() + _budget_s(ctx, 90.0)
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = ec2.run_instances(
                ImageId=ami_id,
                InstanceType="t3.micro",
                MinCount=1,
                MaxCount=1,
                SubnetId=subnet_id,
                IamInstanceProfile={"Name": profile_name},
                TagSpecifications=[
                    {
                        "ResourceType": "instance",
                        "Tags": [
                            {"Key": "Name", "Value": ctx.unique_name("sim2real-ssm-managed-")}
                        ],
                    }
                ],
            )
            instance_id = resp["Instances"][0]["InstanceId"]
            break
        except Exception as exc:  # IAM instance-profile propagation lag
            last_error = exc
            time.sleep(2)
    if instance_id is None:
        if _budget_spent(ctx):
            raise TimeoutError("RunInstances accepting the instance profile: the run budget ended first; "
                               "not graded")
        raise AssertionError(f"could not launch instance (IAM propagation?): {last_error}")

    ctx.on_cleanup(lambda: _safe(lambda: ec2.terminate_instances(InstanceIds=[instance_id])))
    _wait_running(ec2, [instance_id], _budget_s(ctx, 600.0), ctx=ctx)

    _poll_until(
        lambda: ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        ).get("InstanceInformationList", []),
        lambda infos: bool(infos) and infos[0].get("PingStatus") == "Online",
        timeout_s=_budget_s(ctx, 600.0),
        interval_s=2,
        ctx=ctx,
    )
    return instance_id


def _safe(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("InvalidInstanceID.NotFound", "NoSuchEntity"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
