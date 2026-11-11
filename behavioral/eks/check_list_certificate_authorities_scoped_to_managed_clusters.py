"""list-certificate-authorities-scoped-to-managed-clusters."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags


CHECK = "list-certificate-authorities-scoped-to-managed-clusters"
GROUP = "server-side"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListCertificateAuthorities surfaces CAs only for a live, service-provisioned cluster: once
    the cluster is fully deleted, the same call fails ResourceNotFoundException rather than
    returning an empty or stale list."""
    eks = ctx.client("eks")
    cluster = _create_active_cluster(ctx)
    cluster_name = cluster["cluster_name"]

    cas = eks.list_certificate_authorities(clusterName=cluster_name)["certificateAuthorities"]
    assert len(cas) == 1, f"expected exactly one CA on a freshly-created cluster, got {cas!r}"
    assert cas[0]["signingStatus"] == "IN_USE", (
        f"expected signingStatus IN_USE on the fresh cluster's only CA, got {cas[0]!r}"
    )

    _delete_cluster_and_wait(eks, cluster_name, timeout_s=900.0, interval_s=20.0)

    gone_msg = f"No cluster found for name: {cluster_name}."
    cluster_code, cluster_msg = _error_code(lambda: eks.describe_cluster(name=cluster_name))
    assert cluster_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from DescribeCluster on the deleted cluster, got {cluster_code!r}"
    )
    assert cluster_msg == gone_msg, f"DescribeCluster on the deleted cluster -> {cluster_msg!r}"

    ca_list_code, ca_list_msg = _error_code(lambda: eks.list_certificate_authorities(clusterName=cluster_name))
    assert ca_list_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from ListCertificateAuthorities on the deleted "
        f"cluster, got {ca_list_code!r}"
    )
    assert ca_list_msg == gone_msg, f"ListCertificateAuthorities on the deleted cluster -> {ca_list_msg!r}"


# ===== helpers =====

_CLUSTER_CREATE_TIMEOUT_S = 1200.0
_CLUSTER_POLL_INTERVAL_S = 20.0
_FIXTURE_TAGS = {"sim2real:managed": "true", "sim2real": CHECK}


def _error_code(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, because a
    target accepting a call real AWS refuses must not be mistaken for an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=300.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never satisfied within {timeout_s}s, last value={last!r}")


def _create_cluster_with_retry(eks, cluster_name, role_arn, subnet_ids, timeout_s=120.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            eks.create_cluster(
                name=cluster_name,
                roleArn=role_arn,
                resourcesVpcConfig={"subnetIds": subnet_ids},
                tags=_FIXTURE_TAGS,
            )
            return
        except Exception as exc:  # IAM role trust-policy propagation delay
            last_exc = exc
            time.sleep(interval_s)
    raise last_exc


def _delete_cluster_and_wait(eks, cluster_name, timeout_s=600.0, interval_s=15.0):
    from botocore.exceptions import ClientError

    try:
        eks.delete_cluster(name=cluster_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=cluster_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_name} was not deleted within {timeout_s}s")


def _create_active_cluster(ctx):
    """Provision a minimal VPC + IAM role + EKS cluster and wait for ACTIVE."""
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    eks = ctx.client("eks")

    tag_spec = [{"Key": k, "Value": v} for k, v in _FIXTURE_TAGS.items()]

    vpc_id = ec2.create_vpc(
        CidrBlock="10.42.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": tag_spec}],
    )["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    azs = ec2.describe_availability_zones()["AvailabilityZones"]
    subnet_ids = []
    for i in range(2):
        sid = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.42.{i}.0/24",
            AvailabilityZone=azs[i]["ZoneName"],
            TagSpecifications=[{"ResourceType": "subnet", "Tags": tag_spec}],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(lambda sid=sid: _delete_net(ec2, "delete_subnet", SubnetId=sid))

    role_name = ctx.unique_name("sim2real-eks-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=tag_spec
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
        )
    )

    cluster_name = ctx.unique_name("sim2real-eks-")
    _create_cluster_with_retry(eks, cluster_name, role_arn, subnet_ids)
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(eks, cluster_name))

    status = _poll_until(
        lambda: eks.describe_cluster(name=cluster_name)["cluster"]["status"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=_CLUSTER_CREATE_TIMEOUT_S,
        interval_s=_CLUSTER_POLL_INTERVAL_S,
    )
    if status != "ACTIVE":
        raise AssertionError(f"cluster {cluster_name} did not reach ACTIVE, got {status}")

    return {"cluster_name": cluster_name, "role_arn": role_arn, "subnet_ids": subnet_ids, "vpc_id": vpc_id}


# A cluster or other resource in this VPC deletes asynchronously and leaves its ENIs behind for a while,
# so an immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. Teardown
# waits (bounded) for the ENIs, retries DependencyViolation in one window shared by the check's network
# deletes, then raises naming any ENIs still attached. Teardown-only: run() never calls this.
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
