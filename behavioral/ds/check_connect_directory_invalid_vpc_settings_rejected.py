"""connect-directory-invalid-vpc-settings-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "connect-directory-invalid-vpc-settings-rejected"
GROUP = "error-semantics"
SERVICES = ["ds"]
# EC2 only builds the (free) VPC the rejected ConnectDirectory call names.


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ConnectDirectory naming a real VPC and only one of its two real subnets (in distinct AZs) is
    rejected with InvalidParameterException naming the two-subnet rule and creates no directory,
    so the refusal is the subnet-count rule, not an id that fails to resolve."""
    ds = ctx.client("ds")
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-ds-connect").replace("_", "-").rstrip("-")

    zones = sorted({
        z["ZoneName"]
        for z in ec2.describe_availability_zones().get("AvailabilityZones", [])
        if z.get("State") in (None, "available")
    })
    assert len(zones) >= 2, f"need >=2 available AZs to build a valid ConnectSettings, got {zones}"
    az_a, az_b = zones[0], zones[1]

    vpc = ec2.create_vpc(CidrBlock="10.241.0.0/16", TagSpecifications=_tags("vpc", name))["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    subnet_ids = []
    for offset, (cidr, az) in enumerate((("10.241.1.0/24", az_a), ("10.241.2.0/24", az_b)), start=1):
        subnet = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=cidr,
            AvailabilityZone=az,
            TagSpecifications=_tags("subnet", f"{name}-{offset}"),
        )["Subnet"]
        subnet_ids.append(subnet["SubnetId"])
        ctx.on_cleanup(lambda sid=subnet["SubnetId"]: _delete_net(ec2, "delete_subnet", SubnetId=sid))

    # Control: the substrate is real and genuinely spans two AZs, so any refusal below is
    # about the ConnectSettings rule and not about ids that fail to resolve.
    described = ec2.describe_subnets(SubnetIds=subnet_ids)["Subnets"]
    assert {s["AvailabilityZone"] for s in described} == {az_a, az_b}, (
        f"setup is wrong: subnets must land in two distinct AZs {[az_a, az_b]}, got "
        f"{[s['AvailabilityZone'] for s in described]}"
    )
    assert {s["VpcId"] for s in described} == {vpc_id}, (
        f"setup is wrong: both subnets must be in {vpc_id}, got {described}"
    )

    base = dict(Password="TestPassw0rd!23", Size="Small")

    # Negative: break exactly one thing -- the SAME real VPC, ONE of the SAME real subnets.
    negative_name = f"{name}-neg.test"
    bad_directory_id, bad_code, bad_message, bad_request_id = _connect_directory(
        ds,
        dict(
            base,
            Name=negative_name,
            ConnectSettings={
                "VpcId": vpc_id,
                "SubnetIds": [subnet_ids[0]],
                "CustomerDnsIps": ["198.51.100.10"],
                "CustomerUserName": "Administrator",
            },
        ),
    )
    if bad_directory_id is not None:
        # accidental acceptance: reap it before asserting, so cleanup still happens on failure
        ctx.on_cleanup(lambda did=bad_directory_id: _reap(ctx, ds, did))

    assert bad_directory_id is None, (
        f"ConnectDirectory with a single (real, existing) subnet must be rejected, but it "
        f"was ACCEPTED with DirectoryId={bad_directory_id}"
    )
    assert bad_code == "InvalidParameterException", (
        f"ConnectDirectory with exactly one subnet in ConnectSettings must be rejected with "
        f"InvalidParameterException, got {bad_code!r}"
    )
    assert bad_message == (
        f"Invalid subnet ID(s). They must correspond to two subnets in different Availability "
        f"Zones. : RequestId: {bad_request_id}"
    ), f"the refusal must name the two-subnet rule, got {bad_message!r}"

    # Effect absent: independent read confirms no directory was created for the rejected call.
    leaked = [
        d.get("DirectoryId")
        for d in ds.describe_directories().get("DirectoryDescriptions", [])
        if (d.get("Name") or "") == negative_name
    ]
    assert not leaked, f"the rejected ConnectDirectory call must create nothing, found {leaked}"


# ===== helpers =====
def _connect_directory(ds, kwargs):
    """ConnectDirectory(**kwargs); return (DirectoryId, None, None, None) on acceptance, or
    (None, Error.Code, Error.Message, RequestId) on rejection."""
    from botocore.exceptions import ClientError

    try:
        resp = ds.connect_directory(**kwargs)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        request_id = (exc.response.get("ResponseMetadata") or {}).get("RequestId")
        return None, err.get("Code"), err.get("Message"), request_id
    return resp.get("DirectoryId"), None, None, None


def _reap(ctx, ds, directory_id) -> None:
    """Delete a wrongly accepted directory. A connector still being created refuses
    DeleteDirectory with ClientException, retried every 2 s within the cleanup budget."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 1140.0  # with the 630 s network teardown, fits the 1800 s budget
    while True:
        try:
            ds.delete_directory(DirectoryId=directory_id)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "EntityDoesNotExistException":
                return
            if code != "ClientException" or time.monotonic() >= deadline:
                raise
            time.sleep(2.0)


def _tags(resource_type, name):
    return [{
        "ResourceType": resource_type,
        "Tags": [
            {"Key": "Name", "Value": name},
            {"Key": "sim2real", "Value": "behavioral"},
            {"Key": "sim2real-check", "Value": CHECK},
        ],
    }]


# Subnet / VPC deletes fail with DependencyViolation while a deleted directory's ENIs linger: wait
# (bounded) for the ENIs to go, retry DependencyViolation in one window shared by all of a check's
# network deletes, then raise naming the ENIs still attached.
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
        _time.sleep(2)
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
        _time.sleep(2)


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
