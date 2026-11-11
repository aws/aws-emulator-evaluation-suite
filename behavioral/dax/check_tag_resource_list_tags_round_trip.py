"""tag-resource-list-tags-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-list-tags-round-trip"
GROUP = "tagging"
SERVICES = ["dax"]

_NODE_TYPE = "dax.t3.small"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource on a real cluster ARN is visible via ListTags, and a malformed
    ARN passed to ListTags is rejected with InvalidARNFault without disturbing the
    tags that are already attached to the real cluster."""
    dax = ctx.client("dax")
    role_arn = _create_dax_service_role(ctx)
    subnet_ids = _create_vpc_subnets(ctx, count=2)
    subnet_group_name = _create_subnet_group(ctx, subnet_ids)
    cluster_name = ctx.unique_name("sim2real-dax-cl-")

    cluster = _create_cluster(ctx, dax, cluster_name, role_arn, subnet_group_name)
    ctx.on_cleanup(lambda: _safe_delete_cluster(ctx, cluster_name))
    cluster_arn = cluster["ClusterArn"]

    _tag_resource_with_retry(
        dax, cluster_arn, [{"Key": "env", "Value": "sim2real"}, {"Key": "team", "Value": "cache"}]
    )

    tag_map = {t["Key"]: t["Value"] for t in dax.list_tags(ResourceName=cluster_arn)["Tags"]}
    assert tag_map.get("env") == "sim2real", f"expected tag env=sim2real after TagResource, got {tag_map!r}"
    assert tag_map.get("team") == "cache", f"expected tag team=cache after TagResource, got {tag_map!r}"

    code, message = _expect_error(lambda: dax.list_tags(ResourceName="not-a-valid-arn"))
    assert code == "InvalidARNFault", f"ListTags on a malformed ARN returned {code!r}, expected 'InvalidARNFault'"
    assert message == "Input ARN string does not have 7 components.", f"unexpected message: {message!r}"

    # Effect absent: the failed lookup did not disturb the real cluster's tags.
    tags_after = {t["Key"]: t["Value"] for t in dax.list_tags(ResourceName=cluster_arn)["Tags"]}
    assert tags_after.get("env") == "sim2real", (
        f"a rejected ListTags on a malformed ARN disturbed the real cluster's tags: {tags_after!r}"
    )
    assert tags_after.get("team") == "cache", (
        f"a rejected ListTags on a malformed ARN disturbed the real cluster's tags: {tags_after!r}"
    )


# ===== helpers =====
def _expect_error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because a
    target accepting what AWS refuses must not be reported as a mere code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_vpc_subnets(ctx, count=2):
    """DAX's subnet group needs subnets in >=2 AZs. Adopt the run's shared network when one exists,
    and create a dedicated VPC only when the account genuinely has none, so this never depends on an
    ambient shared network existing (a freshly provisioned account may not have one)."""
    ec2 = ctx.client("ec2")
    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if default_vpcs:
        vpc_id = default_vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        if len(subnets) >= count:
            return [s["SubnetId"] for s in subnets[:count]]

    vpc_id = ec2.create_vpc(CidrBlock="10.91.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe_delete_vpc(ctx, vpc_id))
    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(Filters=[{"Name": "region-name", "Values": [ctx.region]}])[
            "AvailabilityZones"
        ]
    ]
    if len(azs) < count:
        raise AssertionError(f"region {ctx.region} has fewer than {count} availability zones")
    subnet_ids = []
    for i, az in enumerate(azs[:count]):
        subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.91.{i}.0/24", AvailabilityZone=az)["Subnet"][
            "SubnetId"
        ]
        ctx.on_cleanup(lambda sid=subnet_id: _safe_delete_subnet(ctx, sid))
        subnet_ids.append(subnet_id)
    return subnet_ids


def _safe_delete_subnet(ctx, subnet_id):
    try:
        _delete_net(ctx.client("ec2"), "delete_subnet", SubnetId=subnet_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidSubnetID.NotFound":
            raise


def _safe_delete_vpc(ctx, vpc_id):
    try:
        _delete_net(ctx.client("ec2"), "delete_vpc", VpcId=vpc_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVpcID.NotFound":
            raise


def _create_subnet_group(ctx, subnet_ids):
    dax = ctx.client("dax")
    name = ctx.unique_name("sim2real-dax-sng-")
    dax.create_subnet_group(SubnetGroupName=name, SubnetIds=subnet_ids)
    ctx.on_cleanup(lambda: _safe_delete_subnet_group(ctx, name))
    return name


def _safe_delete_subnet_group(ctx, name, deadline_s=300.0, interval_s=2.0):
    # The cluster deletes asynchronously and holds the group (SubnetGroupInUseFault) until it is gone.
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            ctx.client("dax").delete_subnet_group(SubnetGroupName=name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("ServiceLinkedRoleNotFoundFault", "SubnetGroupNotFoundFault"):
                return
            if code != "SubnetGroupInUseFault" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _create_dax_service_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-dax-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "dax.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    access_policy = json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "dynamodb:*", "Resource": "*"}]}
    )
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)["Role"]
    iam.put_role_policy(RoleName=role_name, PolicyName="dax-dynamodb-access", PolicyDocument=access_policy)

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="dax-dynamodb-access")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _tag_resource_with_retry(dax, resource_name, tags_list, timeout_s=1200.0, interval_s=20.0):
    """Right after CreateCluster returns, TagResource on that same ARN can answer
    ClusterNotFoundFault ("either not present or not available") until the cluster clears the
    DAX control plane's own propagation/creation delay -- confirmed on real AWS, not assumed.
    Retry the tag call itself (not a fixed sleep) until it succeeds or the deadline passes."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            dax.tag_resource(ResourceName=resource_name, Tags=tags_list)
            return
        except ClientError as err:
            if err.response.get("Error", {}).get("Code") != "ClusterNotFoundFault" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _create_cluster(ctx, dax, cluster_name, role_arn, subnet_group_name, timeout_s=120.0, interval_s=10.0):
    """DAX validates the passed role by checking it can be assumed; IAM's eventual consistency
    means a role created moments ago is not always assumable yet. Retry CreateCluster itself
    (not a fixed sleep) until DAX accepts the role or the deadline passes."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return dax.create_cluster(
                ClusterName=cluster_name,
                NodeType=_NODE_TYPE,
                ReplicationFactor=1,
                IamRoleArn=role_arn,
                SubnetGroupName=subnet_group_name,
            )["Cluster"]
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _safe_delete_cluster(ctx, cluster_name, deadline_s=300.0, interval_s=2.0):
    # DeleteCluster refuses a cluster still changing state (InvalidClusterStateFault); retry that to the deadline.
    dax = ctx.client("dax")
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            dax.delete_cluster(ClusterName=cluster_name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("ClusterNotFoundFault", "ServiceLinkedRoleNotFoundFault"):
                return
            if code != "InvalidClusterStateFault" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


# EC2 network teardown: an async delete leaves AWS-managed ENIs in the subnet for a while, so
# DeleteSubnet/DeleteVpc wait for them and retry DependencyViolation to a shared deadline that
# fits the cleanup budget, then raise naming the ENIs still attached.
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
