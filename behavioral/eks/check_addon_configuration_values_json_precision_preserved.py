"""addon-configuration-values-json-precision-preserved."""
from __future__ import annotations

import json
import time
from collections import deque

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "addon-configuration-values-json-precision-preserved"
GROUP = "representation"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A configurationValues JSON blob with a float and a >2^53 integer is returned by DescribeAddon
    byte-for-byte: no precision loss on either number and no key reordering.
    The addon's health is not asserted: no coredns field takes such values and still renders.
    """
    eks = ctx.client("eks")
    prereqs = _setup_network_and_role(ctx)
    name = ctx.unique_name("sim2real-eks-addoncfg-")
    cluster = _create_active_cluster(ctx, eks, name, prereqs["role_arn"], prereqs["subnet_ids"])

    addon_name = "coredns"
    versions = eks.describe_addon_versions(addonName=addon_name, kubernetesVersion=cluster["version"])["addons"]
    if not versions or not versions[0].get("addonVersions"):
        raise AssertionError(f"no {addon_name} addon versions reported for k8s {cluster['version']}")
    addon_versions = versions[0]["addonVersions"]
    chosen = next((v for v in addon_versions if v.get("compatibilities", [{}])[0].get("defaultVersion")), addon_versions[0])
    addon_version = chosen["addonVersion"]

    schema_text = eks.describe_addon_configuration(addonName=addon_name, addonVersion=addon_version)[
        "configurationSchema"
    ]
    schema = json.loads(schema_text)
    path, kind = _find_open_container(schema)
    if path is None:
        raise AssertionError(
            f"{addon_name} {addon_version} configuration schema exposes no open-ended "
            f"object/array field to carry an arbitrary float+bigint probe "
            f"(top-level properties: {list(schema.get('properties', {}).keys())})"
        )

    float_a, bigint_a = 3.14159265358979, 123456789012345678
    payload_a = _nest_payload(path, kind, float_a, bigint_a)

    eks.create_addon(
        clusterName=name,
        addonName=addon_name,
        addonVersion=addon_version,
        resolveConflicts="OVERWRITE",
        configurationValues=json.dumps(payload_a),
    )
    ctx.on_cleanup(lambda: _best_effort(lambda: eks.delete_addon(clusterName=name, addonName=addon_name)))

    # Any settled status is fine -- see the docstring: the health of a coredns Deployment rendered
    # from an arbitrary topology-spread constraint is not this check's subject, and CREATE_FAILED is
    # the measured outcome for it.
    settled = _wait_addon_settled(ctx, eks, name, addon_name)
    assert settled["status"] != "CREATING", settled["status"]

    described = json.loads(eks.describe_addon(clusterName=name, addonName=addon_name)["addon"]["configurationValues"])
    assert described == payload_a, (
        f"DescribeAddon returned a different configurationValues document than CreateAddon was "
        f"given: sent {payload_a!r}, got {described!r} (addon status {settled['status']!r})"
    )
    leaf = _drill(described, path)
    assert leaf["precisionFloat"] == float_a, (
        f"the float lost precision through the round trip: sent {float_a!r}, got "
        f"{leaf['precisionFloat']!r}"
    )
    assert leaf["precisionBigInt"] == bigint_a, (
        f"the >2^53 integer lost precision through the round trip: sent {bigint_a!r}, got "
        f"{leaf['precisionBigInt']!r} -- a float64 round trip would answer "
        f"{float(bigint_a):.0f}"
    )
    assert isinstance(leaf["precisionBigInt"], int), (
        f"the big integer came back as {type(leaf['precisionBigInt']).__name__}, not int"
    )
    assert list(leaf.keys()) == ["precisionFloat", "precisionBigInt"], (
        f"key order was not preserved through the round trip: {list(leaf.keys())!r}"
    )


# ===== helpers =====
def _resolve_ref(root, node, max_hops=5):
    """Follow a local ``$ref`` (e.g. "#/definitions/Coredns") into ``root``.

    EKS addon configuration schemas commonly root themselves as a bare ``$ref`` into
    ``definitions``/``$defs`` rather than declaring ``properties`` inline, so a
    traversal that only reads ``properties`` never sees the real fields.
    """
    hops = 0
    while isinstance(node, dict) and "$ref" in node and hops < max_hops:
        ref = node["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/"):
            break
        target = root
        for part in ref[2:].split("/"):
            if not isinstance(target, dict) or part not in target:
                return node
            target = target[part]
        node = target
        hops += 1
    return node


def _find_open_container(schema, max_depth=3):
    queue = deque([(_resolve_ref(schema, schema), [])])
    while queue:
        node, path = queue.popleft()
        if not isinstance(node, dict):
            continue
        node_type = node.get("type")
        if node_type == "array" and "items" not in node:
            return path, "array"
        if node_type == "object" and "properties" not in node and node.get("additionalProperties", True) is True:
            return path, "object"
        if len(path) >= max_depth:
            continue
        props = node.get("properties")
        if isinstance(props, dict):
            for key, child in props.items():
                queue.append((_resolve_ref(schema, child), path + [key]))
    return None, None


def _nest_payload(path, kind, float_val, bigint_val):
    leaf = {"precisionFloat": float_val, "precisionBigInt": bigint_val}
    value = [leaf] if kind == "array" else leaf
    for key in reversed(path):
        value = {key: value}
    return value


def _drill(payload, path):
    node = payload
    for key in path:
        node = node[key]
    if isinstance(node, list):
        node = node[0]
    return node


def _best_effort(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _get_or_create_subnets(ctx, ec2):
    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if default_vpcs:
        vpc_id = default_vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        by_az = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        subnet_ids = list(by_az.values())[:2]
        if len(subnet_ids) >= 2:
            return vpc_id, subnet_ids
    vpc_id = ec2.create_vpc(CidrBlock="10.42.0.0/16")["Vpc"]["VpcId"]
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
        subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.42.{i}.0/24", AvailabilityZone=az)["Subnet"][
            "SubnetId"
        ]
        ec2.create_tags(Resources=[subnet_id], Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-eks-subnet-")}])
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)
    return vpc_id, subnet_ids


def _setup_network_and_role(ctx):
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    vpc_id, subnet_ids = _get_or_create_subnets(ctx, ec2)
    role_name = ctx.unique_name("sim2real-eks-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")

    def _cleanup_role():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")
        finally:
            iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup_role)
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "role_arn": role_arn, "role_name": role_name}


def _create_active_cluster(ctx, eks, name, role_arn, subnet_ids, timeout_s=1500, **extra):
    deadline = time.monotonic() + 90
    resp = None
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = eks.create_cluster(
                name=name, roleArn=role_arn, resourcesVpcConfig={"subnetIds": subnet_ids}, **extra
            )
            break
        except Exception as exc:  # fresh IAM role can take a few seconds to propagate
            last_exc = exc
            time.sleep(5)
    if resp is None:
        raise last_exc

    def _cleanup_cluster():
        try:
            eks.delete_cluster(name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_cluster)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = eks.describe_cluster(name=name)["cluster"]
        if desc["status"] == "ACTIVE":
            return desc
        if desc["status"] == "FAILED":
            raise AssertionError(f"cluster {name} entered FAILED status")
        time.sleep(2)
    raise AssertionError(f"cluster {name} did not reach ACTIVE within {timeout_s}s")


def _wait_addon_settled(ctx, eks, cluster_name, addon_name, timeout_s=900):
    """Wait for the addon to leave CREATING, whatever it lands on."""
    deadline = time.monotonic() + timeout_s
    addon = None
    while time.monotonic() < deadline:
        addon = eks.describe_addon(clusterName=cluster_name, addonName=addon_name)["addon"]
        if addon["status"] != "CREATING":
            return addon
        time.sleep(2)
    raise AssertionError(
        f"addon {addon_name} never left CREATING within {timeout_s}s "
        f"(last status {addon['status'] if addon else None!r})"
    )


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
