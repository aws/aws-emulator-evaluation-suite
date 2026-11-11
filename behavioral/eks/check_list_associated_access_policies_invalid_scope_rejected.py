"""list-associated-access-policies-invalid-scope-rejected."""
# ListAssociatedAccessPolicies has no scope filter (accessScope is set by AssociateAccessPolicy), so
# the malformed input is a corrupted nextToken; real AWS rejects it with InvalidParameterException,
# which is outside the operation's declared error set.
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-associated-access-policies-invalid-scope-rejected"
GROUP = "overly-permissive"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListAssociatedAccessPolicies with a corrupted/opaque-violating nextToken is rejected
    with InvalidParameterException rather than silently returning an empty or wrong page,
    while a normal (untokened) call for the same principal keeps working."""
    eks = ctx.client("eks")
    cluster_name = _create_active_cluster(ctx)
    principal_arn = _create_principal_role(ctx)

    # a freshly created IAM role can take a few seconds to propagate before EKS's access-entry
    # principal validation recognizes it; retry through that window
    _retry_while_role_propagates(
        ctx,
        lambda: eks.create_access_entry(clusterName=cluster_name, principalArn=principal_arn, type="STANDARD"),
        "create_access_entry",
        60.0,
    )
    ctx.on_cleanup(lambda: eks.delete_access_entry(clusterName=cluster_name, principalArn=principal_arn))
    eks.associate_access_policy(
        clusterName=cluster_name,
        principalArn=principal_arn,
        policyArn="arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy",
        accessScope={"type": "cluster"},
    )

    baseline = eks.list_associated_access_policies(clusterName=cluster_name, principalArn=principal_arn)
    assert len(baseline["associatedAccessPolicies"]) == 1, (
        f"expected exactly 1 associated access policy after association, got {baseline['associatedAccessPolicies']!r}"
    )

    # break exactly one thing: pass a nextToken that cannot possibly be a real opaque token
    code, message = _error_detail(
        lambda: eks.list_associated_access_policies(
            clusterName=cluster_name, principalArn=principal_arn, nextToken="%%% not a real token %%%"
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException for a corrupted nextToken, got {code!r}"
    expected_message = "The specified nextToken is invalid: unrecognized format."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # positive control: a normal (untokened) call for the same principal still succeeds and is unaffected
    after = eks.list_associated_access_policies(clusterName=cluster_name, principalArn=principal_arn)
    assert len(after["associatedAccessPolicies"]) == 1, (
        f"expected the corrupted nextToken call to leave state unaffected (1 policy), got {after['associatedAccessPolicies']!r}"
    )
    assert after["associatedAccessPolicies"][0]["policyArn"] == "arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy", (
        f"expected AmazonEKSViewPolicy to still be associated, got {after['associatedAccessPolicies'][0]['policyArn']!r}"
    )


# ===== helpers =====
_EKS_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)


def _create_principal_role(ctx: Any) -> str:
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-principal-role-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"}, "Action": "sts:AssumeRole"}],
        }
    )
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _tag_spec(ctx: Any, resource_type: str, name_prefix: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-eks-{name_prefix}-")}],
    }


def _create_cluster_role(ctx: Any) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-role-")
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_EKS_TRUST_POLICY)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")
    )
    return role_arn


def _create_cluster_subnets(ctx: Any) -> list:
    ec2 = ctx.client("ec2")
    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[
                {"Name": "zone-type", "Values": ["availability-zone"]},
                {"Name": "state", "Values": ["available"]},
            ]
        )["AvailabilityZones"]
    ][:2]
    vpc_id = ec2.create_vpc(CidrBlock="10.42.0.0/16", TagSpecifications=[_tag_spec(ctx, "vpc", "vpc")])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.42.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tag_spec(ctx, "subnet", "subnet")],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)
    return subnet_ids


def _retry_while_role_propagates(ctx, call, what, total_s):
    """Retry call every 2 s while EKS rejects a brand-new IAM role that has not propagated yet,
    up to total_s, capped by the run's remaining time."""
    deadline = time.monotonic() + total_s
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, time.monotonic() + max(1.0, left - 5.0))
    while True:
        try:
            return call()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("InvalidParameterException", "ClientException"):
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"{what} kept failing (likely IAM propagation lag): {exc}") from exc
        time.sleep(2)


def _create_active_cluster(ctx: Any) -> str:
    """Creates a minimal EKS cluster (control plane only) and blocks until ACTIVE."""
    eks = ctx.client("eks")
    role_arn = _create_cluster_role(ctx)
    subnet_ids = _create_cluster_subnets(ctx)
    name = ctx.unique_name("sim2real-eks-cluster-")

    # a freshly created/attached IAM role can take a few seconds to propagate before EKS's
    # trust validation recognizes it; retry create_cluster through that window
    _retry_while_role_propagates(
        ctx,
        lambda: eks.create_cluster(
            name=name,
            roleArn=role_arn,
            resourcesVpcConfig={"subnetIds": subnet_ids},
            # CreateAccessEntry requires the cluster's authentication mode to include the
            # EKS API (not just the legacy aws-auth ConfigMap).
            accessConfig={"authenticationMode": "API"},
        ),
        "create_cluster",
        80.0,
    )

    def _cleanup_cluster() -> None:
        try:
            eks.delete_cluster(name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        deadline = time.monotonic() + 900.0
        while time.monotonic() < deadline:
            try:
                eks.describe_cluster(name=name)
            except eks.exceptions.ResourceNotFoundException:
                return
            time.sleep(15.0)

    ctx.on_cleanup(_cleanup_cluster)

    deadline = time.monotonic() + 1200.0
    status = None
    while time.monotonic() < deadline:
        status = eks.describe_cluster(name=name)["cluster"]["status"]
        if status == "ACTIVE":
            return name
        if status == "FAILED":
            raise AssertionError(f"cluster {name} entered FAILED while waiting for ACTIVE")
        time.sleep(2)
    raise AssertionError(f"cluster {name} did not reach ACTIVE within timeout (last status={status})")


def _error_detail(fn) -> Any:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because a
    target accepting input real AWS refuses must not be mistaken for an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(
        f"expected InvalidParameterException for a corrupted nextToken, but the call SUCCEEDED and returned {result!r}"
    )


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
