"""e2e-access-entry-policy-grant-and-revoke-flow."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "e2e-access-entry-policy-grant-and-revoke-flow"
GROUP = "e2e"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListAssociatedAccessPolicies shows an access policy after AssociateAccessPolicy and drops it
    after DisassociateAccessPolicy, so the calls are not accepted no-ops. A deleted access entry
    is ResourceNotFoundException with the exact message."""
    eks = ctx.client("eks")

    subnet_ids = _create_network(ctx)
    cluster_role_arn = _create_role(
        ctx, "cluster", "eks.amazonaws.com", ["arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"]
    )

    cluster_name = ctx.unique_name("sim2real-eks-cl-")
    _create_cluster_with_retry(
        ctx,
        cluster_name,
        cluster_role_arn,
        subnet_ids,
        access_config={"authenticationMode": "API"},
    )
    ctx.on_cleanup(lambda: _best_effort(lambda: eks.delete_cluster(name=cluster_name)))
    _wait_cluster_status(ctx, cluster_name, {"ACTIVE"}, timeout_s=1200)

    principal_arn = _create_role(ctx, "principal", "ec2.amazonaws.com", [])

    _create_access_entry_with_retry(ctx, cluster_name, principal_arn)
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: eks.delete_access_entry(clusterName=cluster_name, principalArn=principal_arn)
        )
    )

    policy_arn = _pick_access_policy_arn(eks)

    eks.associate_access_policy(
        clusterName=cluster_name,
        principalArn=principal_arn,
        policyArn=policy_arn,
        accessScope={"type": "cluster"},
    )

    granted = eks.list_associated_access_policies(clusterName=cluster_name, principalArn=principal_arn)[
        "associatedAccessPolicies"
    ]
    assert any(p["policyArn"] == policy_arn for p in granted), (
        f"expected {policy_arn} in {granted} after AssociateAccessPolicy"
    )

    eks.disassociate_access_policy(clusterName=cluster_name, principalArn=principal_arn, policyArn=policy_arn)

    revoked = eks.list_associated_access_policies(clusterName=cluster_name, principalArn=principal_arn)[
        "associatedAccessPolicies"
    ]
    assert not any(p["policyArn"] == policy_arn for p in revoked), (
        f"expected {policy_arn} removed from associated policies, still present: {revoked}"
    )

    eks.delete_access_entry(clusterName=cluster_name, principalArn=principal_arn)
    code, msg = _error_code(
        lambda: eks.describe_access_entry(clusterName=cluster_name, principalArn=principal_arn)
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from DescribeAccessEntry after DeleteAccessEntry, got {code}"
    )
    expected = "The requested resource does not exist."
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    eks.delete_cluster(name=cluster_name)
    _wait_cluster_deleted(ctx, cluster_name, timeout_s=900)


def _best_effort(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "ResourceNotFoundException"):
            raise


def _error_code(fn):
    """Call fn, require it raises ClientError, return the error (Code, Message)."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("expected the call to fail, but it succeeded")


def _delete_with_retry(fn):
    """Run a network delete (_delete_net retries DependencyViolation); an already-gone
    VPC or subnet is a clean teardown, any other failure raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound"):
            raise


def _pick_access_policy_arn(eks):
    policies = eks.list_access_policies(maxResults=100)["accessPolicies"]
    if not policies:
        raise AssertionError("ListAccessPolicies returned no managed access policies")
    for p in policies:
        if "View" in p["name"]:
            return p["arn"]
    return policies[0]["arn"]


def _create_network(ctx):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.43.0.0/16",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-eks-vpc-")}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    azs = [
        a["ZoneName"] for a in ec2.describe_availability_zones()["AvailabilityZones"] if a["State"] == "available"
    ][:2]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.43.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[
                {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-eks-sn{i}-")}]}
            ],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_with_retry(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid)))
        subnet_ids.append(subnet_id)
    return subnet_ids


def _create_role(ctx, kind, trust_service, managed_policy_arns):
    iam = ctx.client("iam")
    name = ctx.unique_name(f"sim2real-eks-{kind}-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}],
        }
    )
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]
    for policy_arn in managed_policy_arns:
        iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)

    def _cleanup():
        for policy_arn in managed_policy_arns:
            _best_effort(lambda p=policy_arn: iam.detach_role_policy(RoleName=name, PolicyArn=p))
        _best_effort(lambda: iam.delete_role(RoleName=name))

    ctx.on_cleanup(_cleanup)
    return arn


def _create_cluster_with_retry(ctx, name, role_arn, subnet_ids, access_config, timeout_s=90):
    from botocore.exceptions import ClientError

    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            eks.create_cluster(
                name=name,
                roleArn=role_arn,
                resourcesVpcConfig={"subnetIds": subnet_ids},
                accessConfig=access_config,
            )
            return
        except ClientError as err:
            last_err = err
            code = err.response["Error"]["Code"]
            if code in ("InvalidParameterException", "ClientException"):
                time.sleep(2)
                continue
            raise
    raise AssertionError(f"create_cluster never succeeded (IAM propagation?): {last_err}")


def _create_access_entry_with_retry(ctx, cluster_name, principal_arn, timeout_s=120):
    """CreateAccessEntry, retrying the InvalidParameterException a just-created IAM role raises
    until it propagates."""
    from botocore.exceptions import ClientError

    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            eks.create_access_entry(clusterName=cluster_name, principalArn=principal_arn)
            return
        except ClientError as err:
            last_err = err
            code = err.response["Error"]["Code"]
            if code == "InvalidParameterException" and "principal" in str(err).lower():
                time.sleep(5)
                continue
            raise
    raise AssertionError(f"create_access_entry never accepted principal (IAM propagation?): {last_err}")


def _wait_cluster_status(ctx, name, target_statuses, timeout_s, interval_s=15):
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = eks.describe_cluster(name=name)["cluster"]["status"]
        if last in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} status {last} never reached {target_statuses}")


def _wait_cluster_deleted(ctx, name, timeout_s, interval_s=15):
    from botocore.exceptions import ClientError

    eks = ctx.client("eks")
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


# EC2 network teardown waits for AWS-managed ENIs to leave before deleting: dependents in the VPC
# delete asynchronously, so an immediate DeleteSubnet/DeleteVpc fails with DependencyViolation.
# The bounded window is shared by all of one check's network deletes and fits the cleanup budget.
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
