"""server-side-certificate-authority-key-material-managed."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "server-side-certificate-authority-key-material-managed"
GROUP = "server-side"
SERVICES = ["eks"]

_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"

# The exact field set DescribeCertificateAuthority documents for CertificateAuthority.
_DOCUMENTED_CA_FIELDS = {
    "activatedAt", "activatedBy", "createdAt", "createdBy", "data",
    "distributionStatus", "id", "rollbackAvailable", "scheduledEvents",
    "signingStatus", "validity",
}
_FORBIDDEN_KEY_MATERIAL_FIELDS = {
    "privateKey", "privateKeyPem", "keyMaterial", "secretKey", "key", "pemPrivateKey",
}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeCertificateAuthority, for the original signer and for an activated successor CA, never
    returns a private-key-shaped field, and its 'data' is a PEM public certificate."""
    eks = ctx.client("eks")
    cluster = _create_active_eks_cluster(ctx)

    cas = eks.list_certificate_authorities(clusterName=cluster)["certificateAuthorities"]
    ca0_id = cas[0]["id"]
    ca0 = eks.describe_certificate_authority(
        clusterName=cluster, certificateAuthorityId=ca0_id
    )["certificateAuthority"]
    _assert_no_key_material(ca0)

    created = eks.create_certificate_authority(clusterName=cluster)["certificateAuthority"]
    ca1_id = created["id"]
    _wait_ca_distribution_complete(eks, cluster, ca1_id, timeout_s=_capped(ctx, 2400))
    activate = eks.activate_certificate_authority(
        clusterName=cluster, certificateAuthorityId=ca1_id
    )
    _wait_update_successful(eks, cluster, activate["update"]["id"])

    ca1 = eks.describe_certificate_authority(
        clusterName=cluster, certificateAuthorityId=ca1_id
    )["certificateAuthority"]
    _assert_no_key_material(ca1)


def _assert_no_key_material(ca):
    forbidden_present = _FORBIDDEN_KEY_MATERIAL_FIELDS & set(ca.keys())
    assert not forbidden_present, f"CA response exposed key-material-shaped fields: {forbidden_present}"

    unknown_fields = set(ca.keys()) - _DOCUMENTED_CA_FIELDS
    assert not unknown_fields, f"CA response has undocumented fields (possible key leak): {unknown_fields}"

    if "data" in ca and ca["data"]:
        decoded = base64.b64decode(ca["data"] + "===").decode("utf-8", errors="replace")
        assert "BEGIN CERTIFICATE" in decoded, f"CA.data does not look like a public certificate: {decoded[:60]!r}"
        assert "PRIVATE KEY" not in decoded, "CA.data appears to contain private key material"


def _ec2_tags(name):
    return [{"Key": "Name", "Value": name}, {"Key": "sim2real-managed", "Value": "true"}]


def _create_eks_cluster_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-role-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    })
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_CLUSTER_POLICY)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=_CLUSTER_POLICY)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_eks_vpc_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.85.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _ec2_tags(ctx.unique_name("sim2real-eks-vpc-"))}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    azs = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"][:2]]
    subnet_ids = []
    for i, az in enumerate(azs):
        sid = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.85.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _ec2_tags(ctx.unique_name(f"sim2real-eks-sn{i}-"))}],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(lambda sid=sid: _delete_net(ec2, "delete_subnet", SubnetId=sid))
    return subnet_ids


def _wait_cluster_status(eks, name, target, timeout_s=1200, interval_s=20):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = eks.describe_cluster(name=name)["cluster"]["status"]
        if status == target:
            return
        if status == "FAILED":
            raise AssertionError(f"cluster {name} entered FAILED while waiting for {target}")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} did not reach {target} within {timeout_s}s")


def _wait_cluster_gone(eks, name, timeout_s=1200, interval_s=20):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} was not removed within {timeout_s}s")


def _create_active_eks_cluster(ctx):
    eks = ctx.client("eks")
    role_arn = _create_eks_cluster_role(ctx)
    subnet_ids = _create_eks_vpc_subnets(ctx)
    name = ctx.unique_name("sim2real-eks-clu-")
    # EKS rejects a role IAM has not yet propagated with InvalidParameterException: retry that code.
    deadline = time.monotonic() + 60
    while True:
        try:
            eks.create_cluster(name=name, roleArn=role_arn, resourcesVpcConfig={"subnetIds": subnet_ids})
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidParameterException" and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise

    def _cleanup():
        # DeleteCluster answers ResourceInUseException while an update is in flight.
        deadline = time.monotonic() + 600
        while True:
            try:
                eks.delete_cluster(name=name)
                break
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    return
                if code != "ResourceInUseException" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)
        _wait_cluster_gone(eks, name)

    ctx.on_cleanup(_cleanup)
    _wait_cluster_status(eks, name, "ACTIVE")
    return name


def _capped(ctx, cap_s):
    """cap_s, bounded by the run's remaining time less 5 s so the wait fails with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _wait_ca_distribution_complete(eks, cluster, ca_id, timeout_s=900, interval_s=2):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        ca = eks.describe_certificate_authority(
            clusterName=cluster, certificateAuthorityId=ca_id
        )["certificateAuthority"]
        if ca["distributionStatus"] == "COMPLETE":
            return ca
        if ca["distributionStatus"] == "FAILED":
            raise AssertionError(f"CA {ca_id} distribution FAILED")
        time.sleep(interval_s)
    raise AssertionError(f"CA {ca_id} distribution did not complete within {timeout_s}s")


def _wait_update_successful(eks, cluster, update_id, timeout_s=900, interval_s=15):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        update = eks.describe_update(name=cluster, updateId=update_id)["update"]
        if update["status"] == "Successful":
            return update
        if update["status"] in ("Failed", "Cancelled"):
            raise AssertionError(f"update {update_id} ended in {update['status']}")
        time.sleep(interval_s)
    raise AssertionError(f"update {update_id} did not complete within {timeout_s}s")


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes ASYNCHRONOUSLY: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation -- and swallowing that leaked the
# VPC while the check PASSED. So wait (bounded) for the resource's ENIs to go, retry
# DependencyViolation inside the same window, and raise a final failure naming the ENIs still
# attached. Every other error propagates. Teardown-only: nothing run() executes calls this, so it
# cannot change the verdict. The window is shared by all of one check's network deletes.
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
