"""prefix-list-resource-share-association."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "prefix-list-resource-share-association"
GROUP = "resource-share-lifecycle"
SERVICES = ["ram"]


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _wait_association_status(ram, share_arn: str, resource_arn: str, status: str, timeout_s: float = 60.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        pages = ram.get_paginator("get_resource_share_associations").paginate(
            associationType="RESOURCE", resourceShareArns=[share_arn], resourceArn=resource_arn
        )
        associations = [a for page in pages for a in page["resourceShareAssociations"]]
        assert len(associations) == 1, f"expected exactly 1 association, got {associations!r}"
        last = associations[0]["status"]
        if last == status:
            return associations[0]
        time.sleep(2.0)
    raise AssertionError(f"association never reached {status!r}, last seen {last!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A managed prefix list shared with no principals carries the AWS-managed
    default permission for ec2:PrefixList and shows as ASSOCIATED."""
    ec2 = ctx.client("ec2")
    ram = ctx.client("ram")

    pl_name = ctx.unique_name("sim2real-ram-pl-")
    pl = ec2.create_managed_prefix_list(
        PrefixListName=pl_name,
        MaxEntries=2,
        AddressFamily="IPv4",
        Entries=[{"Cidr": "10.93.0.0/24", "Description": "sim2real"}],
    )["PrefixList"]
    pl_id = pl["PrefixListId"]
    pl_arn = pl["PrefixListArn"]
    ctx.on_cleanup(
        _teardown(lambda: ec2.delete_managed_prefix_list(PrefixListId=pl_id), "InvalidPrefixListID.NotFound")
    )

    name = ctx.unique_name("sim2real-ram-plshare-")
    share = ram.create_resource_share(
        name=name,
        resourceArns=[pl_arn],
        tags=[{"key": "sim2real", "value": CHECK}],
    )["resourceShare"]
    share_arn = share["resourceShareArn"]
    ctx.on_cleanup(
        _teardown(lambda: ram.delete_resource_share(resourceShareArn=share_arn), "UnknownResourceException")
    )

    association = _wait_association_status(ram, share_arn, pl_arn, "ASSOCIATED")
    assert association["associatedEntity"] == pl_arn, (
        f"expected associated entity {pl_arn!r}, got {association['associatedEntity']!r}"
    )

    perms = ram.list_resource_share_permissions(resourceShareArn=share_arn)["permissions"]
    assert len(perms) == 1, f"expected exactly 1 permission attached, got {perms!r}"
    assert perms[0]["resourceType"] == "ec2:PrefixList", (
        f"expected resourceType ec2:PrefixList, got {perms[0]['resourceType']!r}"
    )
    assert perms[0]["arn"] == "arn:aws:ram::aws:permission/AWSRAMDefaultPermissionPrefixList", (
        f"expected the AWS-managed default prefix-list permission, got {perms[0]['arn']!r}"
    )
    assert perms[0]["defaultVersion"] is True, (
        f"expected the default permission to be marked defaultVersion, got {perms[0]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
