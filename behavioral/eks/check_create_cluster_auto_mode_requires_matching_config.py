"""create-cluster-auto-mode-requires-matching-config."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-cluster-auto-mode-requires-matching-config"
GROUP = 'overly-permissive'
SERVICES = ['eks']

_EKS_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
_BAD_AZS = {"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"}
_PROPAGATION_HINTS = ("propagat", "assume", "nonexistent role")
_AUTO_MODE_ALL_OR_NOTHING = (
    "For EKS Auto Mode, please ensure that all required configs, including computeConfig, "
    "kubernetesNetworkConfig, and blockStorage are all either fully enabled or fully disabled."
)


# ===== helpers =====
# _stable_error
# is local to this check (see the docstring on it).


def _expect_error(fn):
    """Call fn, require that it raises ClientError, return (Code, Message)."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError("expected the call to fail, but it succeeded")


def _stable_error(fn, *, timeout_s=300, interval_s=15):
    """Call fn until it raises an error that is NOT IAM-propagation noise.

    Returns (Code, Message). 300s is generous for IAM's eventual consistency; the
    hints deliberately exclude the bare word "role" because the assertions here
    are ABOUT a role parameter (nodeRoleArn) and must not be retried away.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            code, msg = err.get("Code", ""), err.get("Message", "")
            low = msg.lower()
            if (
                any(hint in low for hint in _PROPAGATION_HINTS)
                and time.monotonic() < deadline
            ):
                time.sleep(interval_s)
                continue
            return code, msg
        raise AssertionError("expected CreateCluster to be refused, but it succeeded")


def _trust(service):
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": service},
                    "Action": ["sts:AssumeRole"],
                }
            ],
        }
    )


def _delete_role(iam, name):
    try:
        for pol in iam.list_attached_role_policies(RoleName=name).get(
            "AttachedPolicies", []
        ):
            try:
                iam.detach_role_policy(RoleName=name, PolicyArn=pol["PolicyArn"])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _ensure_role(ctx, name, service, managed_policies=()):
    """Create a throwaway IAM role, register teardown, return its ARN.

    No head-start sleep here: every caller reaches this role's ARN through
    _stable_error, which already retries CreateCluster past IAM's propagation
    window (see _PROPAGATION_HINTS) -- a fixed sleep before that would just be
    an unconditional wait, duplicating a wait _stable_error already
    bounds and states a reason for.
    """
    iam = ctx.client("iam")
    try:
        arn = iam.create_role(
            RoleName=name,
            AssumeRolePolicyDocument=_trust(service),
            Description="candidates_09 eks fidelity check",
            Tags=[{"Key": "sim2real:managed", "Value": "true"}],
        )["Role"]["Arn"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("AccessDenied", "AccessDeniedException"):
            raise AssertionError(f"identity cannot create IAM role {name}: {exc}") from exc
        raise
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    for policy_arn in managed_policies:
        iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
    return arn


def _retry_delete(fn):
    """Run a network teardown call (_delete_net retries DependencyViolation itself); a
    not-found code counts as deleted and every other error raises."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound"):
            raise


def _create_dedicated_subnets(ctx):
    """Provision a bare VPC with two subnets in two distinct AZs.

    No internet gateway or route table: CreateCluster validates subnet
    existence/AZ-diversity before it would ever try to reach the network, and
    every call in this check is refused before provisioning, so routability is
    never exercised.
    """
    ec2 = ctx.client("ec2")
    azs = [
        a["ZoneName"]
        for a in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
        if a["ZoneId"] not in _BAD_AZS
    ][:2]
    if len(azs) < 2:
        raise AssertionError(f"need >=2 available EKS-supported AZs, found {len(azs)}")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.91.0.0/16",
        TagSpecifications=[
            {
                "ResourceType": "vpc",
                "Tags": [
                    {"Key": "Name", "Value": ctx.unique_name("sim2real-behav-eks-auto-vpc-")},
                    {"Key": "sim2real:managed", "Value": "true"},
                ],
            }
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))

    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.91.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[
                {
                    "ResourceType": "subnet",
                    "Tags": [
                        {"Key": "Name", "Value": ctx.unique_name(f"sim2real-behav-eks-auto-subnet{i}-")},
                        {"Key": "sim2real:managed", "Value": "true"},
                    ],
                }
            ],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _retry_delete(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid)))
        subnet_ids.append(subnet_id)
    return subnet_ids


def _subnet_ids(ctx):
    """Two subnets in two distinct, EKS-supported AZs.

    Prefers the run's shared network (cheap, nothing to tear down); a
    freshly provisioned account may not have one, so this must not be
    the only path.
    """
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    ).get("Subnets", [])
    by_az: dict[str, str] = {}
    for sn in sorted(subnets, key=lambda s: s["AvailabilityZone"]):
        if sn["AvailabilityZoneId"] in _BAD_AZS:
            continue
        by_az.setdefault(sn["AvailabilityZone"], sn["SubnetId"])
    if len(by_az) >= 2:
        return [by_az[az] for az in sorted(by_az)][:2]
    return _create_dedicated_subnets(ctx)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """EKS Auto Mode is all-or-nothing: computeConfig.enabled=true is refused unless block storage and
    elastic load balancing are enabled with it, node pools are refused without a node role, and an
    all-disabled config passes this validation (failing only on its single-AZ subnets)."""
    c = ctx.client("eks")
    if "computeConfig" not in c.meta.service_model.operation_model(
        "CreateCluster"
    ).input_shape.members:
        raise AssertionError(
            "this botocore does not model CreateCluster.computeConfig (EKS Auto Mode)"
        )
    role_arn = _ensure_role(
        ctx,
        ctx.unique_name("sim2real-behav-eks-auto-"),
        "eks.amazonaws.com",
        [_EKS_CLUSTER_POLICY],
    )
    node_role_arn = _ensure_role(
        ctx, ctx.unique_name("sim2real-behav-eks-node-"), "ec2.amazonaws.com"
    )
    subnets = _subnet_ids(ctx)
    name = ctx.unique_name("sim2real-behav-eks-auto-")

    def create(**overrides):
        body = {
            "name": name,
            "roleArn": role_arn,
            "resourcesVpcConfig": {"subnetIds": subnets},
        }
        body.update(overrides)
        return lambda: c.create_cluster(**body)

    # --- Break 1: compute enabled, storage and load balancing untouched.
    code, msg = _stable_error(create(computeConfig={"enabled": True}))
    assert code == "InvalidParameterException", (
        f"computeConfig.enabled=true with no storageConfig and no "
        f"elasticLoadBalancing -> {code}: {msg}; Auto Mode requires all three"
    )
    assert msg == _AUTO_MODE_ALL_OR_NOTHING, msg

    # --- Break 2: two of the three enabled -- still incoherent.
    code, msg = _stable_error(
        create(
            computeConfig={"enabled": True, "nodeRoleArn": node_role_arn},
            storageConfig={"blockStorage": {"enabled": True}},
        )
    )
    assert code == "InvalidParameterException", (
        f"computeConfig+storageConfig enabled but elasticLoadBalancing left "
        f"disabled -> {code}: {msg}; partial Auto Mode must be refused"
    )
    assert msg == _AUTO_MODE_ALL_OR_NOTHING, msg

    # --- Break 3: all three enabled, node pools requested, but no node role.
    code, msg = _stable_error(
        create(
            computeConfig={"enabled": True, "nodePools": ["general-purpose"]},
            storageConfig={"blockStorage": {"enabled": True}},
            kubernetesNetworkConfig={"elasticLoadBalancing": {"enabled": True}},
        )
    )
    assert code == "InvalidParameterException", (
        f"computeConfig.nodePools without nodeRoleArn -> {code}: {msg}; a node "
        f"pool has no identity to run instances under"
    )
    assert msg == "When Compute Config nodeRoleArn is null or empty, nodePool list cannot be populated.", msg

    # --- Effect absent.
    code, msg = _expect_error(lambda: c.describe_cluster(name=name))
    assert code == "ResourceNotFoundException", (
        f"a refused Auto Mode CreateCluster still materialised {name}: {code}"
    )
    assert msg == f"No cluster found for name: {name}.", msg
    assert name not in c.list_clusters(maxResults=100).get("clusters", []), (
        f"{name} appeared in ListClusters after three refused CreateCluster calls"
    )

    # --- Control: explicitly all-disabled is a coherent non-Auto Mode config and must
    #     get past Auto Mode validation. Paired with a single-AZ subnet set so it
    #     still cannot provision.
    code, msg = _stable_error(
        lambda: c.create_cluster(
            name=name,
            roleArn=role_arn,
            resourcesVpcConfig={"subnetIds": subnets[:1]},
            computeConfig={"enabled": False},
            storageConfig={"blockStorage": {"enabled": False}},
            kubernetesNetworkConfig={"elasticLoadBalancing": {"enabled": False}},
        )
    )
    assert code == "InvalidParameterException", (
        f"all-disabled Auto Mode + single-AZ subnets -> {code}: {msg}"
    )
    assert msg == "Subnets specified must be in at least two different AZs", (
        f"an explicitly all-disabled config must pass Auto Mode validation and "
        f"fail on the subnets instead: {msg!r}"
    )
    code, msg = _expect_error(lambda: c.describe_cluster(name=name))
    assert code == "ResourceNotFoundException", (
        f"the control CreateCluster still materialised {name}: {code}"
    )
    assert msg == f"No cluster found for name: {name}.", msg


# EC2 network teardown: a cluster in this VPC deletes asynchronously and its ENIs keep DeleteSubnet /
# DeleteVpc failing with DependencyViolation for minutes, so wait for the ENIs, retry that code to one
# deadline shared by the check's network deletes, then raise naming the ENIs still attached.
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
