"""create-computer-authentication-failed-rejected."""
from __future__ import annotations

import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-computer-authentication-failed-rejected"
GROUP = "overly-permissive"
SERVICES = ["ds"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateComputer on a directory that is not yet Active fails DirectoryUnavailableException;
    once Active the request succeeds and echoes the computer name and a Description attribute,
    and repeating the same name fails EntityAlreadyExistsException.
    """
    vpc_id, subnet_ids = _create_ds_vpc(ctx)
    ds = ctx.client("ds")
    directory_id, _ = _create_microsoft_ad(ctx, vpc_id, subnet_ids)

    computer_name = f"sim2real{random.randint(0, 9999999)}"[:15]

    # Negative: the directory has just been requested and is nowhere near Active yet (real
    # Managed Microsoft AD provisioning takes tens of minutes), so CreateComputer against it
    # now is rejected rather than silently accepted. It is the first call after the create, so
    # no extra request widens the gap; the stage is read afterwards for the failure message.
    try:
        code, message, request_id = _error(
            lambda: ds.create_computer(
                DirectoryId=directory_id, ComputerName=computer_name, Password="Sim2Real-Computer-Pw1!"
            )
        )
    except AssertionError as exc:
        stage = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]["Stage"]
        raise AssertionError(f"{exc} (directory stage after the call: {stage})") from exc
    assert code == "DirectoryUnavailableException", f"expected DirectoryUnavailableException, got {code!r}"
    expected_message = f"Directory: '{directory_id}' does not exist. : RequestId: {request_id}"
    assert message == expected_message, f"unexpected error message: {message!r}"

    _wait_for_directory_stage(ctx, directory_id, {"Active"}, timeout_s=_budget_s(ctx, 2700.0))

    # Positive control: once Active, CreateComputer succeeds and the response body genuinely
    # reflects what we asked for (not just an empty 200 OK).
    marker_value = ctx.unique_name("sim2real-marker-")
    resp = ds.create_computer(
        DirectoryId=directory_id,
        ComputerName=computer_name,
        Password="Sim2Real-Computer-Pw1!",
        ComputerAttributes=[{"Name": "description", "Value": marker_value}],
    )
    computer = resp["Computer"]
    assert computer["ComputerName"] == computer_name, (
        f"expected ComputerName={computer_name!r}, got {computer['ComputerName']!r}"
    )
    assert computer["ComputerId"], "CreateComputer response is missing ComputerId"
    attrs_raw = computer.get("ComputerAttributes", [])
    assert attrs_raw, f"expected ComputerAttributes to be populated in the response, got {attrs_raw!r}"
    attr_values = {a["Name"]: a["Value"] for a in attrs_raw}
    # Real AWS echoes the attribute back re-cased to "Description" (Pascal case), not the
    # lowercase "description" name set in the request.
    assert attr_values.get("Description") == marker_value, (
        f"expected Description attribute {marker_value!r}, got attrs={attr_values!r}"
    )

    # Effect absent for the earlier rejection: creating the SAME computer name again now
    # fails with EntityAlreadyExistsException rather than silently overwriting/duplicating it,
    # confirming the first (rejected) attempt never actually created anything.
    dup_code, dup_message, dup_request_id = _error(
        lambda: ds.create_computer(
            DirectoryId=directory_id, ComputerName=computer_name, Password="Sim2Real-Computer-Pw2!"
        )
    )
    assert dup_code == "EntityAlreadyExistsException", f"expected EntityAlreadyExistsException, got {dup_code!r}"
    expected_dup_message = (
        f"Could not create computer. RequestId: {dup_request_id} : RequestId: {dup_request_id}"
    )
    assert dup_message == expected_dup_message, f"unexpected error message: {dup_message!r}"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _error(fn) -> tuple[str, str, str]:
    """(code, message) of the AWS error raised by fn(); raises if fn() unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", ""), exc.response["ResponseMetadata"]["RequestId"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _create_ds_vpc(ctx):
    ec2 = ctx.client("ec2")
    octet = random.randint(0, 200)
    deadline = time.monotonic() + 120
    vpc = None
    last_exc = None
    while vpc is None and time.monotonic() < deadline:
        try:
            vpc = ec2.create_vpc(
                CidrBlock=f"10.{octet}.0.0/23",
                TagSpecifications=[{
                    "ResourceType": "vpc",
                    "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ds-vpc-")}],
                }],
            )["Vpc"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "VpcLimitExceeded":
                raise
            # Concurrent fixture creation can transiently hold the VPC quota; back off and retry.
            last_exc = exc
            octet = random.randint(0, 200)
            time.sleep(2)
    if vpc is None:
        raise last_exc
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, vpc_id, f"vpc {vpc_id}", lambda: ec2.delete_vpc(VpcId=vpc_id)))
    azs = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"]][:2]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.{octet}.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{
                "ResourceType": "subnet",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ds-subnet-")}],
            }],
        )["Subnet"]
        subnet_id = subnet["SubnetId"]
        subnet_ids.append(subnet_id)
        ctx.on_cleanup(
            lambda sid=subnet_id: _delete_net(ec2, vpc_id, f"subnet {sid}", lambda: ec2.delete_subnet(SubnetId=sid))
        )
    return vpc_id, subnet_ids


def _create_microsoft_ad(ctx, vpc_id, subnet_ids, edition="Standard", password="Sim2Real-Ds-Pw924!"):
    ds = ctx.client("ds")
    name = f"{ctx.unique_name('sim2real-ds-')}.example.com".lower()
    resp = ds.create_microsoft_ad(
        Name=name,
        Password=password,
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
        Edition=edition,
        Tags=[{"Key": "sim2real", "Value": "behavioral"}, {"Key": "sim2real-check", "Value": CHECK}],
    )
    directory_id = resp["DirectoryId"]
    # Unwrapped (not _safe): a swallowed delete failure would leave the directory running.
    ctx.on_cleanup(lambda: ds.delete_directory(DirectoryId=directory_id))
    return directory_id, name


def _wait_for_directory_stage(ctx, directory_id, target_stages, timeout_s=2700, interval_s=2):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    stage = None
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
        stage = desc["Stage"]
        if stage in target_stages:
            return desc
        if stage == "Failed":
            raise AssertionError(f"directory {directory_id} entered Failed stage: {desc.get('StageReason')}")
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"directory {directory_id} reaching {target_stages}: the run budget ended first; not graded")
    raise AssertionError(
        f"directory {directory_id} did not reach {target_stages} within {timeout_s}s (last stage={stage})"
    )


# Network teardown waits (bounded) for AWS-managed ENIs to leave: directories and similar
# resources delete asynchronously, so an immediate DeleteSubnet/DeleteSecurityGroup/DeleteVpc
# fails DependencyViolation. Retry within one shared window, then raise naming the ENIs left.
_NET_TEARDOWN_S = 840.0
_NET_DEADLINES: dict = {}


def _delete_net(ec2, vpc_id, label, delete) -> None:
    deadline = _NET_DEADLINES.setdefault(vpc_id, time.monotonic() + _NET_TEARDOWN_S)
    while _vpc_enis(ec2, vpc_id) and time.monotonic() < deadline:
        time.sleep(2)
    while True:
        try:
            delete()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code.endswith(".NotFound"):
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise RuntimeError(
                    f"{label}: {code}; ENIs still in {vpc_id}: {_vpc_enis(ec2, vpc_id)}"
                ) from exc
        time.sleep(2)


def _vpc_enis(ec2, vpc_id) -> list:
    try:
        enis = ec2.describe_network_interfaces(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
    except ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [
        f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}"
        for e in enis["NetworkInterfaces"]
    ]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
