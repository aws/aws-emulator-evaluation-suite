"""deploy-cluster-active-and-api-reachable."""
from __future__ import annotations

import base64
import json
import ssl
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen


from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "deploy-cluster-active-and-api-reachable"
GROUP = "deploy"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A cluster deployed via a CFN template reaches ACTIVE and its control-plane
    API server is actually reachable over HTTPS (native protocol), not just a
    stack that reports CREATE_COMPLETE with a stubbed cluster record."""
    net = _create_vpc_with_subnets(ctx)
    role_arn = _create_cluster_role(ctx)
    cluster_name = ctx.unique_name("sim2real-ekscl-")

    template = json.dumps(
        {
            "Resources": {
                "Cluster": {
                    "Type": "AWS::EKS::Cluster",
                    "Properties": {
                        "Name": cluster_name,
                        "RoleArn": role_arn,
                        "ResourcesVpcConfig": {
                            "SubnetIds": net["subnet_ids"],
                            "EndpointPublicAccess": True,
                            "EndpointPrivateAccess": False,
                        },
                    },
                }
            },
            "Outputs": {"ClusterName": {"Value": {"Ref": "Cluster"}}},
        }
    )
    _deploy_cfn_stack(ctx, template, timeout_s=1500)

    eks = ctx.client("eks")
    cluster = eks.describe_cluster(name=cluster_name)["cluster"]
    assert cluster["status"] == "ACTIVE", f"cluster status is {cluster['status']!r}, not ACTIVE"
    got_subnets = sorted(cluster["resourcesVpcConfig"]["subnetIds"])
    want_subnets = sorted(net["subnet_ids"])
    assert got_subnets == want_subnets, f"cluster subnetIds {got_subnets!r}, expected {want_subnets!r}"

    assert _cluster_in_list(eks, cluster_name), "cluster does not appear in ListClusters"

    status, body = _poll_until(
        lambda: _http_get_k8s_version(ctx, cluster, cluster_name, with_auth=True),
        lambda sb: sb[0] == 200,
        timeout_s=90.0,
        interval_s=10.0,
    )
    assert status == 200, f"authenticated GET /version returned HTTP {status}, expected 200"
    assert "gitVersion" in body, f"unexpected /version payload: {body!r}"

    anon_status, _ = _http_get_k8s_version(ctx, cluster, cluster_name, with_auth=False)
    assert anon_status == 401, (
        f"unauthenticated GET /version returned HTTP {anon_status}, expected 401 "
        "-- the endpoint must be a real k8s API server enforcing IAM auth, not an open reachable IP"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last value={value!r})")
        time.sleep(interval_s)
        value = probe()
    return value


def _tagspec_ec2(resource_type, name):
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _create_vpc_with_subnets(ctx):
    ec2 = ctx.client("ec2")
    tag = ctx.unique_name("sim2real-eksvpc")
    vpc_id = ec2.create_vpc(CidrBlock="10.42.0.0/16", TagSpecifications=[_tagspec_ec2("vpc", tag)])["Vpc"]["VpcId"]
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    azs = [
        a["ZoneName"]
        for a in ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
            "AvailabilityZones"
        ]
    ][:2]
    subnet_ids = []
    for i, az in enumerate(azs):
        sid = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.42.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tagspec_ec2("subnet", f"{tag}-{i}")],
        )["Subnet"]["SubnetId"]
        ec2.modify_subnet_attribute(SubnetId=sid, MapPublicIpOnLaunch={"Value": True})
        subnet_ids.append(sid)
    igw_id = ec2.create_internet_gateway(TagSpecifications=[_tagspec_ec2("internet-gateway", tag)])[
        "InternetGateway"
    ]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    rt_id = ec2.create_route_table(VpcId=vpc_id, TagSpecifications=[_tagspec_ec2("route-table", tag)])[
        "RouteTable"
    ]["RouteTableId"]
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    for sid in subnet_ids:
        ec2.associate_route_table(RouteTableId=rt_id, SubnetId=sid)

    # Register cleanups in reverse-of-execution order (LIFO teardown): subnets
    # first, then route table, then detach+delete the IGW, then the VPC last.
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ctx.on_cleanup(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id))
    ctx.on_cleanup(lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id))
    ctx.on_cleanup(lambda: ec2.delete_route_table(RouteTableId=rt_id))
    for sid in subnet_ids:
        ctx.on_cleanup(lambda sid=sid: ec2.delete_subnet(SubnetId=sid))
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids}


def _create_cluster_role(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-eks-cluster-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn))
    return role_arn


def _stack_status(cfn, stack_name):
    try:
        return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    except ClientError:
        return None


def _deploy_cfn_stack(ctx, template_body, timeout_s=1500):
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-eks-stack-")

    def _cleanup():
        cfn.delete_stack(StackName=stack_name)
        _poll_until(
            lambda: _stack_status(cfn, stack_name),
            lambda s: s is None or s == "DELETE_COMPLETE",
            timeout_s=timeout_s,
            interval_s=15.0,
        )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )
    ctx.on_cleanup(_cleanup)
    status = _poll_until(
        lambda: _stack_status(cfn, stack_name),
        lambda s: s in ("CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"),
        timeout_s=timeout_s,
        interval_s=15.0,
    )
    if status != "CREATE_COMPLETE":
        raise AssertionError(f"stack {stack_name} ended in {status}, expected CREATE_COMPLETE")
    return stack_name


def _cluster_in_list(eks, name):
    paginator_kwargs = {}
    while True:
        resp = eks.list_clusters(**paginator_kwargs)
        if name in resp.get("clusters", []):
            return True
        token = resp.get("nextToken")
        if not token:
            return False
        paginator_kwargs = {"nextToken": token}


def _http_get_k8s_version(ctx, cluster, cluster_name, with_auth):
    """GET /version on the cluster's control-plane endpoint, authenticated the
    same way kubectl/aws-iam-authenticator do: a short-lived bearer token made
    from a SigV4-presigned `sts:GetCallerIdentity` URL, tagged with the
    `x-k8s-aws-id` header so EKS's IAM authenticator webhook can map our IAM
    identity to a Kubernetes user. EKS gives the IAM identity that created the
    cluster Kubernetes cluster-admin permissions, so this identity is
    authorized -- an anonymous request (no header) gets HTTP 401."""
    ca_pem = base64.b64decode(cluster["certificateAuthority"]["data"]).decode("ascii")
    ssl_ctx = ssl.create_default_context(cadata=ca_pem)
    endpoint = cluster["endpoint"]
    headers = {"Authorization": f"Bearer {_get_bearer_token(ctx, cluster_name)}"} if with_auth else {}
    target, route = ctx.endpoint_route(endpoint.rstrip("/") + "/version")
    req = Request(target, method="GET", headers={**headers, **route})
    try:
        with urlopen(req, context=ssl_ctx, timeout=15) as resp:
            return resp.status, json.loads(resp.read())
    except HTTPError as e:
        return e.code, {}


def _get_bearer_token(ctx, cluster_name):
    """Build a k8s-aws-v1 bearer token exactly as `aws eks get-token` does: a
    presigned (but never sent) GetCallerIdentity request, base64url-encoded."""
    sts = ctx.client("sts")
    signer = sts._request_signer
    region = ctx.region
    url = ctx.service_url(f"https://sts.{ctx.region}.amazonaws.com") + "/?Action=GetCallerIdentity&Version=2011-06-15"
    params = {
        "method": "GET",
        "url": url,
        "body": {},
        "headers": {"x-k8s-aws-id": cluster_name},
        "context": {},
    }
    signed_url = signer.generate_presigned_url(
        params, region_name=region, expires_in=60, operation_name="GetCallerIdentity"
    )
    encoded = base64.urlsafe_b64encode(signed_url.encode("utf-8")).decode("utf-8").rstrip("=")
    return "k8s-aws-v1." + encoded


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
