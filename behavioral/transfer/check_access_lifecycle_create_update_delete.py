"""access-lifecycle-create-update-delete."""
from __future__ import annotations

import json
import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "access-lifecycle-create-update-delete"
GROUP = "state-machine"
SERVICES = ["transfer"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An access on an AWS_DIRECTORY_SERVICE server reflects UpdateAccess's HomeDirectory, and
    after DeleteAccess describe and update raise ResourceNotFoundException and it is unlisted."""
    transfer = ctx.client("transfer")

    vpc_id, az_subnets = _all_az_subnets(ctx)
    directory_id, subnet_ids = _create_directory(ctx, vpc_id, az_subnets)

    role_arn = _create_transfer_role(ctx, "access")

    server_id = _create_server_with_directory(
        ctx, directory_id=directory_id, vpc_id=vpc_id, subnet_id=subnet_ids[0]
    )
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=server_id))

    external_id = _sid(ctx)
    bucket = ctx.unique_name("sim2real-bucket")

    transfer.create_access(
        ServerId=server_id,
        ExternalId=external_id,
        Role=role_arn,
        HomeDirectoryType="PATH",
        HomeDirectory=f"/{bucket}/home1",
    )
    deleted = {"v": False}

    def _cleanup_access():
        if not deleted["v"]:
            transfer.delete_access(ServerId=server_id, ExternalId=external_id)

    ctx.on_cleanup(_cleanup_access)

    described = transfer.describe_access(ServerId=server_id, ExternalId=external_id)["Access"]
    assert described["HomeDirectory"] == f"/{bucket}/home1", (
        f"expected HomeDirectory=/{bucket}/home1 right after CreateAccess, got {described['HomeDirectory']!r}"
    )

    transfer.update_access(
        ServerId=server_id,
        ExternalId=external_id,
        HomeDirectory=f"/{bucket}/home2",
    )
    updated = transfer.describe_access(ServerId=server_id, ExternalId=external_id)["Access"]
    assert updated["HomeDirectory"] == f"/{bucket}/home2", (
        f"UpdateAccess(HomeDirectory=/{bucket}/home2) did not take effect, "
        f"DescribeAccess still reports {updated['HomeDirectory']!r}"
    )

    transfer.delete_access(ServerId=server_id, ExternalId=external_id)
    deleted["v"] = True

    code, message = _error_code(
        lambda: transfer.describe_access(ServerId=server_id, ExternalId=external_id)
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from DescribeAccess after DeleteAccess, got {code!r}"
    )
    assert message == "Unknown access", message

    # A mutation on the deleted access mapping also fails, not just a read.
    update_code, update_message = _error_code(
        lambda: transfer.update_access(
            ServerId=server_id, ExternalId=external_id, HomeDirectory=f"/{bucket}/home3"
        )
    )
    assert update_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from UpdateAccess on a deleted access mapping, got {update_code!r}"
    )
    assert update_message == "Unknown access", update_message

    listed = transfer.list_accesses(ServerId=server_id)["Accesses"]
    assert all(a["ExternalId"] != external_id for a in listed), (
        f"deleted ExternalId {external_id} still present in ListAccesses: {listed}"
    )


def _sid(ctx) -> str:
    return f"S-1-1-{int(time.time())}-{random.randint(100000, 999999)}"


def _error_code(fn):
    """Call fn(); return its error code and message. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _all_az_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError(f"need subnets in >=2 AZs for a directory, found {len(by_az)}")
    return vpc_id, sorted(by_az.items())


def _create_directory(ctx, vpc_id: str, az_subnets: list[tuple[str, str]]):
    """Create a Microsoft AD, trying successive AZ pairs because some AZs are not valid for
    Directory Service. Returns (directory_id, subnet_ids_used)."""
    ds = ctx.client("ds")
    name_base = ctx.unique_name("sim2real-behav-access").lower().replace("_", "-")
    last_err = None
    for i in range(len(az_subnets) - 1):
        subnet_ids = [az_subnets[i][1], az_subnets[i + 1][1]]
        try:
            resp = ds.create_microsoft_ad(
                Name=f"{name_base}-{i}.test",
                Password="Sim2Real-Passw0rd!23",
                VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
                Edition="Standard",
                Tags=[{"Key": "sim2real", "Value": "true"}],
            )
            directory_id = resp["DirectoryId"]

            def _cleanup_directory():
                deadline = time.monotonic() + 60.0
                last = None
                while time.monotonic() < deadline:
                    try:
                        ds.delete_directory(DirectoryId=directory_id)
                        return
                    except ClientError as e2:
                        code = e2.response["Error"]["Code"]
                        if code == "EntityDoesNotExistException":
                            return
                        if code != "ClientException":
                            raise
                        last = e2
                        time.sleep(2.0)
                raise RuntimeError(f"directory {directory_id} was not deleted: {last!r}") from last

            ctx.on_cleanup(_cleanup_directory)
            return directory_id, subnet_ids
        except ClientError as e:
            last_err = e
            if "Availability Zone" in str(e):
                continue
            raise
    raise AssertionError(f"CreateMicrosoftAD never accepted any AZ pair: {last_err}")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _create_server_with_directory(ctx, *, directory_id: str, vpc_id: str, subnet_id: str) -> str:
    """CreateServer once the new Microsoft AD is Active (commonly 20-45 minutes on AWS),
    retrying InvalidRequestException/InternalServiceError while it settles."""
    transfer = ctx.client("transfer")
    ds = ctx.client("ds")
    # Past the 45-minute upper end of the usual creation time, still capped by the run budget.
    deadline = time.monotonic() + _budget_s(ctx, 3600.0)
    stage = None
    while time.monotonic() < deadline:
        dirs = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"]
        stage = dirs[0].get("Stage") if dirs else None
        if stage in ("Active", "Failed", "Impaired", "Inoperable"):
            break
        time.sleep(2.0)
    if stage not in ("Active", "Failed", "Impaired", "Inoperable") and _budget_spent(ctx):
        raise TimeoutError(f"directory {directory_id} reaching Active: the run budget ended first; not graded")
    if stage != "Active":
        raise AssertionError(
            f"Microsoft AD directory {directory_id} did not reach Active in time (Stage={stage!r})"
        )
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = transfer.create_server(
                IdentityProviderType="AWS_DIRECTORY_SERVICE",
                IdentityProviderDetails={"DirectoryId": directory_id},
                EndpointType="VPC",
                EndpointDetails={"VpcId": vpc_id, "SubnetIds": [subnet_id]},
                Tags=[{"Key": "sim2real", "Value": "true"}],
            )
            return resp["ServerId"]
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] in ("InvalidRequestException", "InternalServiceError"):
                time.sleep(2.0)
                continue
            raise
    if _budget_spent(ctx):
        raise TimeoutError("CreateServer accepting the Active directory: the run budget ended first; not graded")
    raise AssertionError(
        "CreateServer(AWS_DIRECTORY_SERVICE) never accepted the freshly created "
        f"Active Microsoft AD directory in time (last error: {last_err})"
    )


def _create_transfer_role(ctx, suffix: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-transfer-{suffix}-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "transfer.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="inline",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline"))
    _wait_for_role(ctx, role_name)
    return role_arn


def _wait_for_role(ctx, role_name, timeout_s=30.0, interval_s=2.0):
    iam = ctx.client("iam")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=role_name)
            return
        except ClientError:
            time.sleep(interval_s)
    raise AssertionError(f"IAM role {role_name} never became visible within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

