"""create-certificate-authority-resource-limit-exceeded-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-certificate-authority-resource-limit-exceeded-rejected"
GROUP = "overly-permissive"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """With the signer and one successor CA, a further CreateCertificateAuthority fails with
    InvalidRequestException and AWS's exact "maximum number of certificate authorities (2)" message and the
    CA set is unchanged; after the successor is deleted the same create succeeds.
    """
    eks = ctx.client("eks")
    subnet_ids = _create_own_subnets(ctx)
    role_arn = _create_role(ctx, "eks.amazonaws.com", ["AmazonEKSClusterPolicy"])

    cluster_name = ctx.unique_name("sim2real-eks-caq-")
    _create_cluster_with_retry(ctx, eks, cluster_name, role_arn, subnet_ids)
    ctx.on_cleanup(lambda: _safe_delete_cluster(ctx, eks, cluster_name))
    _wait_cluster_status(ctx, eks, cluster_name, "ACTIVE", timeout_s=1500)

    initial = eks.list_certificate_authorities(clusterName=cluster_name)["certificateAuthorities"]
    assert len(initial) == 1, f"freshly created cluster should have exactly 1 CA, found {len(initial)}"
    outgoing_id = initial[0]["id"]

    # Positive control: appending the FIRST successor (bringing the cluster to the
    # documented two-CA cap) is a normal, successful write.
    created = eks.create_certificate_authority(clusterName=cluster_name)
    successor_id = created["certificateAuthority"]["id"]
    update_id = created["update"]["id"]
    assert successor_id != outgoing_id, f"successor CA id {successor_id!r} must differ from outgoing CA id {outgoing_id!r}"

    # Let the append operation itself settle (distinct from the longer, separate
    # distribution-to-managed-components process) so a subsequent rejection is
    # unambiguously about the two-CA cap, not a lingering "update in progress" state.
    append_status = _wait_update_terminal(ctx, eks, cluster_name, update_id, timeout_s=600)
    assert append_status == "Successful", f"successor CA append update ended in {append_status!r}, not Successful"

    after_first = eks.list_certificate_authorities(clusterName=cluster_name)["certificateAuthorities"]
    assert len(after_first) == 2, f"expected exactly 2 CAs after appending the first successor, got {len(after_first)}"

    # Negative: the cluster is now at the documented two-CA cap. Appending a second
    # successor must be rejected, not silently accepted as a third CA.
    code, message = _error(lambda: eks.create_certificate_authority(clusterName=cluster_name))
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code!r}"
    assert message == (
        "Cluster already has the maximum number of certificate authorities (2). "
        "Delete an existing CA before creating a new one."
    ), f"unexpected message: {message!r}"

    # Effect absent: the CA set is unchanged -- still exactly the outgoing CA plus the
    # one successor, no phantom third entry.
    final = eks.list_certificate_authorities(clusterName=cluster_name)["certificateAuthorities"]
    final_ids = {c["id"] for c in final}
    assert final_ids == {outgoing_id, successor_id}, f"CA set changed after rejected create: {final_ids}"

    # Restore: delete the successor CA we appended, which brings the cluster back
    # under the two-CA cap, then demonstrate the IDENTICAL create call now succeeds.
    # This is what separates "rejected because the cluster is at its cap" from
    # "rejected outright" -- the same call must work again once the cap is lifted.
    delete_resp = eks.delete_certificate_authority(clusterName=cluster_name, certificateAuthorityId=successor_id)
    delete_status = _wait_update_terminal(ctx, eks, cluster_name, delete_resp["update"]["id"], timeout_s=600)
    assert delete_status == "Successful", f"delete of successor CA {successor_id} ended in {delete_status!r}, not Successful"

    restored = eks.list_certificate_authorities(clusterName=cluster_name)["certificateAuthorities"]
    restored_ids = {c["id"] for c in restored}
    assert restored_ids == {outgoing_id}, f"expected only the outgoing CA after deleting the successor, got {restored_ids}"

    recreated = eks.create_certificate_authority(clusterName=cluster_name)
    recreated_id = recreated["certificateAuthority"]["id"]
    assert recreated_id not in (outgoing_id, successor_id), (
        f"recreated successor id {recreated_id!r} collided with a prior CA id"
    )
    recreate_status = _wait_update_terminal(ctx, eks, cluster_name, recreated["update"]["id"], timeout_s=600)
    assert recreate_status == "Successful", (
        f"the identical create-certificate-authority call ended in {recreate_status!r} after the cap was lifted"
    )

    after_restore = eks.list_certificate_authorities(clusterName=cluster_name)["certificateAuthorities"]
    after_restore_ids = {c["id"] for c in after_restore}
    assert after_restore_ids == {outgoing_id, recreated_id}, (
        f"expected exactly the outgoing CA plus the newly recreated successor, got {after_restore_ids}"
    )


def _error(fn):
    """Run fn, which must fail; return the (code, message) AWS sent."""
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("call succeeded but was expected to fail")


def _create_own_subnets(ctx) -> list[str]:
    ec2 = ctx.client("ec2")
    vpc_name = ctx.unique_name("sim2real-eks-caq-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.61.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": vpc_name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe_delete_vpc(ec2, vpc_id))

    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[
                {"Name": "zone-type", "Values": ["availability-zone"]},
                {"Name": "state", "Values": ["available"]},
            ]
        )["AvailabilityZones"]
    ][:2]
    if len(azs) < 2:
        raise AssertionError(f"region does not have at least 2 available availability zones, found {len(azs)}")

    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_name = ctx.unique_name("sim2real-eks-caq-subnet-")
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.61.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": subnet_name}]}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _safe_delete_subnet(ec2, sid))
        subnet_ids.append(subnet_id)
    return subnet_ids


def _safe_delete_subnet(ec2, subnet_id: str) -> None:
    """Delete the subnet; an already-deleted one is fine, any other failure raises."""
    try:
        _delete_net(ec2, "delete_subnet", SubnetId=subnet_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidSubnetID.NotFound":
            raise


def _safe_delete_vpc(ec2, vpc_id: str) -> None:
    """Delete the VPC; an already-deleted one is fine, any other failure raises."""
    try:
        _delete_net(ec2, "delete_vpc", VpcId=vpc_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVpcID.NotFound":
            raise


def _create_role(ctx, service_principal: str, managed_policy_names: list[str]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": service_principal}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "Name", "Value": role_name}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe_delete_role(ctx, role_name, managed_policy_names))
    for policy_name in managed_policy_names:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=f"arn:aws:iam::aws:policy/{policy_name}")
    return role_arn


def _safe_delete_role(ctx, role_name: str, managed_policy_names: list[str]) -> None:
    iam = ctx.client("iam")
    for policy_name in managed_policy_names:
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=f"arn:aws:iam::aws:policy/{policy_name}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_cluster_with_retry(ctx, eks, name: str, role_arn: str, subnet_ids: list[str], timeout_s: float = 180.0) -> None:
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    last_code = None
    while time.monotonic() < deadline:
        try:
            eks.create_cluster(
                name=name,
                roleArn=role_arn,
                resourcesVpcConfig={"subnetIds": subnet_ids},
                tags={"Name": name},
            )
            return
        except ClientError as err:
            last_code = err.response["Error"]["Code"]
            if last_code == "ClientException":
                time.sleep(2.0)
                continue
            raise
    raise AssertionError(f"CreateCluster kept failing with {last_code} after {timeout_s}s (IAM role propagation?)")


def _wait_cluster_status(ctx, eks, name: str, want: str, timeout_s: float, interval_s: float = 20.0) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = eks.describe_cluster(name=name)["cluster"]["status"]
        if last == want:
            return
        if last == "FAILED":
            raise AssertionError(f"cluster {name} entered FAILED while waiting for {want}")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} did not reach {want} within {timeout_s}s (last={last})")


def _wait_cluster_gone(ctx, eks, name: str, timeout_s: float, interval_s: float = 15.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=name)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} was not deleted within {timeout_s}s")


def _safe_delete_cluster(ctx, eks, name: str) -> None:
    try:
        eks.delete_cluster(name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    _wait_cluster_gone(ctx, eks, name, timeout_s=900)


def _wait_update_terminal(ctx, eks, cluster_name: str, update_id: str, timeout_s: float, interval_s: float = 10.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = eks.describe_update(name=cluster_name, updateId=update_id)["update"]["status"]
        if last in ("Successful", "Failed", "Cancelled"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"update {update_id} on {cluster_name} did not reach a terminal status within {timeout_s}s (last={last})")


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes asynchronously: its ENIs
# outlive its delete, so an immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with
# DependencyViolation. Wait (bounded) for the ENIs to go, retry DependencyViolation in the same
# window shared by all of one check's network deletes, then raise naming the ENIs still attached.
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
