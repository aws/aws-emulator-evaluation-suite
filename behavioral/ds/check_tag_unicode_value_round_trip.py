"""tag-unicode-value-round-trip."""
from __future__ import annotations

import time
from itertools import combinations

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "tag-unicode-value-round-trip"
GROUP = "representation"
SERVICES = ["ds"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag key/value with unicode characters survives AddTagsToResource -> ListTagsForResource byte-identical."""
    vpc_id, candidate_subnet_ids = _diff_az_subnets(ctx)
    ds = ctx.client("ds")

    # CreateDirectory (Simple AD) is rejected ("Simple AD is no longer open to new customers"),
    # so the directory is an AWS Managed Microsoft AD.
    directory_id = _create_microsoft_ad_with_az_retry(
        ds, _domain_name(ctx, "tag"), _ds_password(), vpc_id, candidate_subnet_ids
    )
    ctx.on_cleanup(lambda: _delete_directory_when_ready(ctx, directory_id))

    # AddTagsToResource rejects a directory still in "Creating" with ClientException
    # ("operation is not supported for directories in this state"), so the check waits for
    # Active before tagging.
    desc = _wait_for_directory_stage(
        ctx, directory_id, {"Active", "Failed", "Impaired", "Inoperable"}, timeout_s=2700
    )
    assert desc["Stage"] == "Active", f"directory did not reach Active, stage={desc['Stage']!r}"

    # DS tag keys/values are constrained to the pattern ^([\p{L}\p{Z}\p{N}_.:/=+\-@]*)$ --
    # Unicode letters/separators/numbers plus that punctuation set. Emoji fall under the
    # Unicode "Symbol" category, which AddTagsToResource rejects with a ValidationException,
    # so this exercises multi-script Unicode letters instead of emoji.
    unicode_key = "cl\u00e9-\u952e-\u00dcber"
    unicode_value = "v\u00e0lue-\u5024-\u03a9_zone:west/dept=eng+1-caf\u00e9@example.com"
    ds.add_tags_to_resource(ResourceId=directory_id, Tags=[{"Key": unicode_key, "Value": unicode_value}])

    tags = ds.list_tags_for_resource(ResourceId=directory_id)["Tags"]
    matches = [t for t in tags if t["Key"] == unicode_key]
    assert len(matches) == 1, f"expected exactly one tag with the unicode key, got {tags!r}"
    assert matches[0]["Value"] == unicode_value, (
        f"unicode tag value mismatch: {matches[0]['Value']!r} != {unicode_value!r}"
    )


def _ds_password() -> str:
    return "Sim2Real-Test1234!"


def _domain_name(ctx, kind: str) -> str:
    base = ctx.unique_name(f"sim2real-ds-{kind}-")
    return f"{base}.test"


def _diff_az_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get("Subnets", [])
    subnets = sorted((s for s in subnets if s.get("AvailabilityZoneId") not in _DS_UNSUPPORTED_ZONE_IDS), key=lambda s: s["AvailabilityZone"])
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError("VPC has subnets in fewer than 2 distinct AZs; a directory needs 2")
    return vpc_id, list(by_az.values())


def _create_microsoft_ad_with_az_retry(ds, name, password, vpc_id, subnet_ids):
    # DS refuses some AZs as "capacity constrained" (ClientException "Failed to locate
    # Availability Zone ... may be capacity constrained"), so try every distinct-AZ subnet pair
    # rather than pinning which AZs to avoid.
    attempted = []
    for pair in combinations(subnet_ids, 2):
        try:
            return ds.create_microsoft_ad(
                Name=name,
                Password=password,
                Edition="Standard",
                VpcSettings={"VpcId": vpc_id, "SubnetIds": list(pair)},
            )["DirectoryId"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            if code == "ClientException" and "Availability Zone" in msg:
                attempted.append((pair, msg))
                continue
            raise
    raise AssertionError(
        f"no distinct-AZ subnet pair among {subnet_ids} was accepted by CreateMicrosoftAD: {attempted}"
    )


def _wait_for_directory_stage(ctx, directory_id, target_stages, timeout_s, interval_s=20):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    stage = None
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
        stage = desc["Stage"]
        if stage in target_stages:
            return desc
        time.sleep(interval_s)
    raise AssertionError(
        f"directory {directory_id} did not reach {target_stages} within {timeout_s}s (last stage={stage})"
    )


def _delete_directory_when_ready(ctx, directory_id, timeout_s=1700.0):
    """Delete the directory and wait until it reads Deleted, within the 1800 s cleanup budget.
    DeleteDirectory answers ClientException while the directory is still being created, so that
    answer is retried every 2 s within the same deadline."""
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ds.delete_directory(DirectoryId=directory_id)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "EntityDoesNotExistException":
                return
            if code != "ClientException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    while True:
        try:
            found = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "EntityDoesNotExistException":
                return
            raise
        if not found or found[0]["Stage"] == "Deleted":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"directory {directory_id} still {found[0]['Stage']!r} {timeout_s:.0f}s into teardown")
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
