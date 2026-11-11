"""certificate-authority-csr-base64-blob-round-trip."""
from __future__ import annotations

import base64
import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "certificate-authority-csr-base64-blob-round-trip"
GROUP = "representation"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The base64-encoded public certificate blob (`certificateAuthority.data`) returned by
    DescribeCertificateAuthority for a newly appended successor CA decodes to identical bytes
    across repeated reads -- it isn't re-encoded or truncated between calls."""
    eks = ctx.client("eks")
    cluster = _create_active_cluster(ctx)

    resp = eks.create_certificate_authority(clusterName=cluster["name"])
    ca_id = resp["certificateAuthority"]["id"]
    ctx.on_cleanup(
        lambda: _delete_certificate_authority_when_idle(eks, cluster["name"], ca_id)
    )

    # The public cert data may populate asynchronously right after CreateCertificateAuthority
    # returns; poll until it is present before comparing repeated reads.
    described_1 = _poll_until(
        lambda: eks.describe_certificate_authority(
            clusterName=cluster["name"], certificateAuthorityId=ca_id
        )["certificateAuthority"],
        lambda ca: bool(ca.get("data")),
        timeout_s=180.0,
        interval_s=5.0,
    )
    data_1 = described_1["data"]
    decoded_1 = base64.b64decode(data_1)
    assert len(decoded_1) > 0

    described_2 = eks.describe_certificate_authority(
        clusterName=cluster["name"], certificateAuthorityId=ca_id
    )["certificateAuthority"]
    data_2 = described_2["data"]
    decoded_2 = base64.b64decode(data_2)

    assert data_2 == data_1, "base64 blob changed between repeated DescribeCertificateAuthority reads"
    assert decoded_2 == decoded_1, "decoded certificate bytes changed between repeated reads"

    reencoded_1 = base64.b64encode(decoded_1).decode("ascii")
    assert reencoded_1 == data_1, (
        f"data blob is not canonically base64-encoded: re-encoding the decoded bytes produced "
        f"{reencoded_1!r}, not the original {data_1!r}"
    )


def _get_two_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        by_az: dict[str, str] = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        if len(by_az) >= 2:
            return list(by_az.values())[:2]

    # No usable default VPC (a freshly provisioned account may not have one) -- provision a
    # minimal VPC with subnets in two AZs instead of depending on an ambient default.
    vpc_id = ec2.create_vpc(CidrBlock="10.43.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-eks-vpc-")}])
    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
            "AvailabilityZones"
        ]
    ][:2]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.43.{i}.0/24", AvailabilityZone=az)["Subnet"][
            "SubnetId"
        ]
        ec2.create_tags(Resources=[subnet_id], Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-eks-subnet-")}])
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)
    if len(subnet_ids) < 2:
        raise AssertionError(f"region has fewer than two available AZs ({azs!r}); cannot provision an EKS cluster")
    return subnet_ids


def _create_cluster_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _poll_until(probe, predicate, timeout_s=1200.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _wait_cluster_status(ctx, name, statuses, timeout_s=1200.0, interval_s=15.0):
    eks = ctx.client("eks")
    return _poll_until(
        lambda: eks.describe_cluster(name=name)["cluster"],
        lambda c: c["status"] in statuses,
        timeout_s=timeout_s,
        interval_s=interval_s,
    )


def _create_active_cluster(ctx):
    eks = ctx.client("eks")
    name = ctx.unique_name("sim2real-eks-")
    subnets = _get_two_subnets(ctx)
    role_arn = _create_cluster_role(ctx)
    eks.create_cluster(name=name, roleArn=role_arn, resourcesVpcConfig={"subnetIds": subnets})

    def _cleanup():
        try:
            _wait_cluster_status(ctx, name, {"ACTIVE", "FAILED"}, timeout_s=1200.0)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        _delete_eks_cluster_and_wait(eks, name)

    ctx.on_cleanup(_cleanup)
    desc = _wait_cluster_status(ctx, name, {"ACTIVE", "FAILED"}, timeout_s=1200.0)
    if desc["status"] != "ACTIVE":
        raise AssertionError(f"cluster {name} entered status {desc['status']} instead of ACTIVE")
    return {"name": name, "arn": desc["arn"], "role_arn": role_arn, "subnets": subnets}


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes ASYNCHRONOUSLY: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation -- and swallowing that leaks the VPC
# while the check passes, until the account's VPC quota fails later checks. So wait
# (bounded) for the resource's ENIs to go, retry DependencyViolation inside the same window, and raise
# a final failure naming the ENIs still attached. Every other error propagates.
# Teardown-only: nothing run() executes calls this, so it cannot change the verdict. The window is
# shared by all of one check's network deletes and fits the suite's 1800 s cleanup budget.
_NET_TEARDOWN_S = 1260.0
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


def _delete_certificate_authority_when_idle(eks, cluster_name, ca_id, timeout_s=900.0, interval_s=20.0):
    """DeleteCertificateAuthority, retried while an earlier CA update on the cluster still runs."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            eks.delete_certificate_authority(clusterName=cluster_name, certificateAuthorityId=ca_id)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _delete_eks_cluster_and_wait(eks, name, timeout_s=1200.0, interval_s=20.0):
    """Delete an EKS cluster and wait until it is gone, so its ENIs leave the network.

    DeleteCluster is refused while an update, node group or add-on operation still runs; that
    ResourceInUseException is retried until the deadline.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            eks.delete_cluster(name=name)
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"EKS cluster {name} still exists {timeout_s:.0f}s after DeleteCluster")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
