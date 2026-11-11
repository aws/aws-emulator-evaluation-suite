"""enable-sso-without-prerequisites-denied."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "enable-sso-without-prerequisites-denied"
GROUP = "overly-permissive"
SERVICES = ["ds"]

_PASSWORD = "Sim2Real-Sso-2024!"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """EnableSso on a directory with no access URL/alias is rejected with ClientException rather
    than silently turning single sign-on on: the admin guide requires the access URL first."""
    ds = ctx.client("ds")
    vpc_id, subnet_ids = _create_vpc_with_subnets(ctx)

    name = f"{ctx.unique_name('sim2real-ds-sso').rstrip('-').lower()}.example.com"
    directory_id = ds.create_microsoft_ad(
        Name=name,
        Password=_PASSWORD,
        Edition="Standard",
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
    )["DirectoryId"]
    ctx.on_cleanup(lambda: _delete_directory_and_wait(ds, directory_id))

    _wait_directory_active(ds, directory_id, timeout_s=2700.0)

    baseline = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
    assert baseline.get("SsoEnabled") is False, f"expected a fresh directory to have SSO disabled, got {baseline.get('SsoEnabled')!r}"
    # Per API_DirectoryDescription.html: "If no alias exists, the alias is the directory
    # identifier" - so "no access URL/alias configured yet" shows up as Alias == DirectoryId,
    # not as an empty/missing field.
    assert baseline.get("Alias") == directory_id, (
        f"expected Alias to default to the directory id {directory_id!r} before CreateAlias, "
        f"got {baseline.get('Alias')!r}"
    )

    # Break exactly one thing: try to enable SSO before an access URL/alias exists.
    err = _client_error(lambda: ds.enable_sso(DirectoryId=directory_id))
    code = err.response["Error"]["Code"]
    assert code == "ClientException", f"expected ClientException, got {code}"
    expected_message = (
        f"An alias is required before enabling SSO. DomainId={directory_id} "
        f": RequestId: {err.response['ResponseMetadata']['RequestId']}"
    )
    message = err.response["Error"].get("Message")
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # Effect absent: SSO was NOT silently turned on.
    after_reject = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
    assert after_reject.get("SsoEnabled") is False, (
        f"EnableSso was rejected but SsoEnabled is {after_reject.get('SsoEnabled')!r}, expected False"
    )

    # Positive control: fix the one missing prerequisite (create the access URL/alias),
    # then the exact same EnableSso call succeeds.
    alias = ctx.unique_name("sim2real-ds-sso-").rstrip("-").lower()
    ds.create_alias(DirectoryId=directory_id, Alias=alias)
    after_alias = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
    assert after_alias.get("Alias") == alias, f"expected Alias {alias!r} after CreateAlias, got {after_alias.get('Alias')!r}"
    ds.enable_sso(DirectoryId=directory_id)
    enabled = _wait_sso_enabled(ds, directory_id, True, timeout_s=300.0)
    assert enabled is True, f"expected SsoEnabled to become True after CreateAlias+EnableSso, got {enabled!r}"
    ctx.on_cleanup(lambda: _disable_sso_best_effort(ds, directory_id))


# ===== helpers =====
def _client_error(fn):
    """Call fn(); return the ClientError it raises. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _create_vpc_with_subnets(ctx, cidr_prefix: str = "10.97"):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock=f"{cidr_prefix}.0.0/16",
        TagSpecifications=[
            {
                "ResourceType": "vpc",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ds-vpc-")}],
            }
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    azs = [a["ZoneName"] for a in ec2.describe_availability_zones()["AvailabilityZones"]][:2]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"{cidr_prefix}.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[
                {
                    "ResourceType": "subnet",
                    "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ds-subnet-")}],
                }
            ],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)
    return vpc_id, subnet_ids


def _wait_directory_active(ds, directory_id, timeout_s=2700.0, interval_s=30.0):
    deadline = time.monotonic() + timeout_s
    stage = None
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
        stage = desc["Stage"]
        if stage == "Active":
            return desc
        if stage == "Failed":
            raise AssertionError(f"directory {directory_id} entered Failed stage")
        time.sleep(interval_s)
    raise AssertionError(f"directory {directory_id} did not reach Active (last stage={stage})")


def _wait_sso_enabled(ds, directory_id, desired: bool, timeout_s=300.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0].get("SsoEnabled")
        if status == desired:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"SsoEnabled did not reach {desired} within {timeout_s}s (last={status})")


def _disable_sso_best_effort(ds, directory_id):
    from botocore.exceptions import ClientError

    try:
        ds.disable_sso(DirectoryId=directory_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DirectoryDoesNotExistException",
            "EntityDoesNotExistException",
            "UserDoesNotExistException",
        ):
            raise


def _delete_directory_and_wait(ds, directory_id, timeout_s=1100.0, interval_s=20.0):
    """Delete the directory and wait until it 404s or shows the terminal Stage "Deleted"; the
    window leaves the network teardown its share of the suite's cleanup budget."""
    from botocore.exceptions import ClientError

    try:
        ds.delete_directory(DirectoryId=directory_id)
    except ClientError as err:
        if err.response["Error"]["Code"] == "EntityDoesNotExistException":
            return
        raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            descs = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "EntityDoesNotExistException":
                return
            raise
        if not descs or descs[0]["Stage"] == "Deleted":
            return
        time.sleep(interval_s)
    raise AssertionError(f"directory {directory_id} was not deleted within {timeout_s}s of DeleteDirectory")


# AWS-managed ENIs leave a VPC asynchronously after their owner's delete returns, so a network
# delete waits (bounded, within the cleanup budget) for them and retries DependencyViolation, then
# raises naming the ENIs still attached. Teardown-only: run() never calls this.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
