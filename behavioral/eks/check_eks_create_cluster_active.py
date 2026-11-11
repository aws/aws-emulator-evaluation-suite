"""eks-create-cluster-active."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eks-create-cluster-active"
GROUP = 'data-plane'
SERVICES = ['eks']

_EKS_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
_FIXTURE_TAGS = {"sim2real:managed": "true", "sim2real": CHECK}
_CLUSTER_GONE_TIMEOUT_S = 1200
_ROLE_PROPAGATION_TIMEOUT_S = 180
# The harness's per-check budget for this suite: the provisioning and deletion waits end only
# where the runner would stop the check anyway, so neither is an assertion on elapsed time.
_SUITE_BUDGET_S = 3600


def _trust(service: str, extra_actions: tuple[str, ...] = ()) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": service},
                    "Action": ["sts:AssumeRole", *extra_actions],
                }
            ],
        }
    )

def _create_role(ctx, name, service="eks.amazonaws.com", managed_policies=()):
    """Create a per-run IAM role, attach its managed policies, and register its cleanup."""
    iam = ctx.client("iam")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_trust(service),
        Description="SimParityProbe EKS behavioral fidelity fixture",
        Tags=[{"Key": k, "Value": v} for k, v in _FIXTURE_TAGS.items()],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    for policy_arn in managed_policies:
        iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
        ctx.on_cleanup(lambda arn=policy_arn: iam.detach_role_policy(RoleName=name, PolicyArn=arn))
    return arn

def _wait_for(fn, pred, timeout_s=300, interval_s=5, desc=""):
    deadline = time.time() + timeout_s
    while True:
        last = fn()
        if pred(last):
            return last
        if time.time() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting for {desc}; last={last!r}")
        time.sleep(interval_s)

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A created cluster reaches ACTIVE with an endpoint, PEM certificate data, and its ARN, role, subnets and
    tag as requested; after deletion Describe and Update fail with ResourceNotFoundException (4xx, exact
    message) and ListClusters omits it.
    """
    c = ctx.client("eks")
    name = ctx.unique_name("sim2real-behav-eks-active-")
    # Create the cluster role and the VPC subnets this run owns; each registers its cleanup.
    role_arn = _create_role(ctx, ctx.unique_name("sim2real-eks-role-"), "eks.amazonaws.com", [_EKS_CLUSTER_POLICY])
    subnet_ids = _create_network(ctx)
    deadline = time.monotonic() + _ROLE_PROPAGATION_TIMEOUT_S
    while True:
        try:
            c.create_cluster(
                name=name,
                roleArn=role_arn,
                resourcesVpcConfig={
                    "subnetIds": subnet_ids,
                    "endpointPublicAccess": True,
                    "endpointPrivateAccess": False,
                },
                tags=dict(_FIXTURE_TAGS),
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidParameterException" and time.monotonic() < deadline:
                # IAM is eventually consistent: EKS rejects a brand-new role until it propagates.
                time.sleep(2)
                continue
            raise
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(c, name))

    resp = _wait_for(
        lambda: c.describe_cluster(name=name),
        lambda r: r["cluster"]["status"] in ("ACTIVE", "FAILED"),
        timeout_s=_SUITE_BUDGET_S,
        interval_s=20,
        desc=f"cluster {name} status==ACTIVE",
    )
    cluster = resp["cluster"]
    assert cluster["status"] == "ACTIVE", f"unexpected status {cluster['status']!r}"
    assert cluster.get("endpoint"), "ACTIVE cluster is missing its API server endpoint"
    ca = cluster.get("certificateAuthority") or {}
    assert ca.get("data"), "ACTIVE cluster is missing certificateAuthority.data"
    pem = base64.b64decode(ca["data"]).decode("ascii", "replace")
    assert pem.startswith("-----BEGIN CERTIFICATE-----"), (
        f"certificateAuthority.data does not decode to a PEM certificate: {pem[:40]!r}"
    )
    # The independent read returns what this check supplied at create.
    expected_arn = f"arn:aws:eks:{ctx.region}:{ctx.account}:cluster/{name}"
    assert cluster.get("arn") == expected_arn, f"cluster arn {cluster.get('arn')!r}, expected {expected_arn!r}"
    assert cluster.get("roleArn") == role_arn, f"roleArn {cluster.get('roleArn')!r}, expected {role_arn!r}"
    got_subnets = set((cluster.get("resourcesVpcConfig") or {}).get("subnetIds") or [])
    assert got_subnets == set(subnet_ids), f"subnetIds {sorted(got_subnets)!r}, expected {sorted(subnet_ids)!r}"
    got_tag = (cluster.get("tags") or {}).get("sim2real")
    assert got_tag == CHECK, f"cluster tag sim2real={got_tag!r}, expected {CHECK!r}"

    # Delete, poll to the terminal outcome (gone), then prove it unreadable, unlisted, unusable.
    c.delete_cluster(name=name)
    _wait_for(
        lambda: _cluster_exists(c, name),
        lambda exists: not exists,
        timeout_s=_SUITE_BUDGET_S,
        interval_s=20,
        desc=f"cluster {name} to be deleted",
    )
    code, status, message = _error(lambda: c.describe_cluster(name=name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert isinstance(status, int) and 400 <= status < 500, f"expected HTTP 4xx describing the deleted cluster, got {status}"
    expected_message = f"No cluster found for name: {name}."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"
    listed = [n for page in c.get_paginator("list_clusters").paginate() for n in page["clusters"]]
    assert name not in listed, "the deleted cluster is still listed by ListClusters"
    code, status, message = _error(
        lambda: c.update_cluster_config(name=name, resourcesVpcConfig={"endpointPublicAccess": True})
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException updating the deleted cluster, got {code!r}"
    )
    assert isinstance(status, int) and 400 <= status < 500, f"expected HTTP 4xx updating the deleted cluster, got {status}"
    expected_message = f"No cluster found for name: {name}."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its ClientError (code, HTTP status, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return (
            exc.response.get("Error", {}).get("Code"),
            exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
            exc.response.get("Error", {}).get("Message") or "",
        )
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _cluster_exists(c, name) -> bool:
    try:
        c.describe_cluster(name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return False
        raise
    return True


def _delete_cluster_and_wait(c, name) -> None:
    # DeleteCluster refuses with ResourceInUseException while an update is in progress;
    # retry inside the same window.
    deadline = time.monotonic() + _CLUSTER_GONE_TIMEOUT_S
    while True:
        try:
            c.delete_cluster(name=name)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(20)
    while time.monotonic() < deadline and _cluster_exists(c, name):
        time.sleep(20)


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _create_network(ctx) -> list[str]:
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.42.0.0/16",
        TagSpecifications=[_tag_spec("vpc", ctx.unique_name("sim2real-eks-vpc-"))],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    azs = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    az_names = [az["ZoneName"] for az in azs][:2]
    assert len(az_names) >= 2, "region needs at least two availability zones"

    subnet_ids = []
    for i, az in enumerate(az_names):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.42.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tag_spec("subnet", ctx.unique_name(f"sim2real-eks-subnet{i}-"))],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)
    return subnet_ids


# EC2 network teardown waits (bounded) for the cluster's AWS-managed ENIs to leave the subnet
# before it deletes, retries DependencyViolation inside the same window, and raises a final
# failure naming the ENIs. Teardown-only: nothing run() executes calls this.
_NET_TEARDOWN_S = 1260.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    from botocore.exceptions import ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and time.monotonic() < deadline:
        time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
