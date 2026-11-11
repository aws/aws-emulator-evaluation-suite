"""deploy-eks-cluster-cloudformation-active."""
from __future__ import annotations

import base64
import json
import ssl
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-eks-cluster-cloudformation-active"
GROUP = "deploy"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "dp:endpoint", "plane:control", "plane:data")
def run(ctx) -> None:
    """An EKS::Cluster deployed via CloudFormation reaches real ACTIVE, not just CREATE_COMPLETE."""
    vpc = _create_vpc_infra(ctx)
    role_arn = _create_cluster_role(ctx)
    cluster_name = ctx.unique_name("sim2real-eks-cfn-")

    def _assert_cluster_gone_after_teardown():
        eks = ctx.client("eks")
        try:
            eks.describe_cluster(name=cluster_name)
        except eks.exceptions.ResourceNotFoundException:
            return
        raise AssertionError(f"cluster {cluster_name} is still describable after stack teardown")

    # Registered before the stack-delete cleanup below, so LIFO teardown runs the
    # stack delete FIRST and this proof-of-gone SECOND.
    ctx.on_cleanup(_assert_cluster_gone_after_teardown)

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "ClusterName": {"Type": "String"},
            "RoleArn": {"Type": "String"},
            "SubnetIds": {"Type": "List<AWS::EC2::Subnet::Id>"},
        },
        "Resources": {
            "EksCluster": {
                "Type": "AWS::EKS::Cluster",
                "Properties": {
                    "Name": {"Ref": "ClusterName"},
                    "RoleArn": {"Ref": "RoleArn"},
                    "ResourcesVpcConfig": {"SubnetIds": {"Ref": "SubnetIds"}},
                },
            }
        },
        "Outputs": {
            "ClusterNameOut": {"Value": {"Ref": "EksCluster"}},
            "ClusterEndpointOut": {"Value": {"Fn::GetAtt": ["EksCluster", "Endpoint"]}},
        },
    }
    result = _deploy_stack(
        ctx,
        template,
        {"ClusterName": cluster_name, "RoleArn": role_arn, "SubnetIds": ",".join(vpc["subnet_ids"])},
        create_timeout_s=1500,
    )
    assert result["outputs"]["ClusterNameOut"] == cluster_name

    eks = ctx.client("eks")
    cluster = eks.describe_cluster(name=cluster_name)["cluster"]
    assert cluster["status"] == "ACTIVE", f"cluster status is {cluster['status']!r}, not ACTIVE"
    assert cluster["endpoint"].startswith("https://")
    assert cluster["certificateAuthority"]["data"], "cluster reports no CA data"

    # A stack-level CREATE_COMPLETE plus stubbed ACTIVE/endpoint/CA fields is not proof the
    # cluster is real: TLS-handshake the actual control-plane endpoint against the CA it
    # reported and read the live Kubernetes API's own unauthenticated-401 response. A target
    # that never provisions a real API server cannot produce this without also standing one up.
    status, body = _poll_until(
        lambda: _tls_probe_k8s_api(ctx, cluster),
        lambda sb: sb[0] is not None,
        timeout_s=90.0,
        interval_s=10.0,
    )
    assert status == 401, f"unauthenticated GET /version returned HTTP {status}, expected 401"
    assert body.get("kind") == "Status" and body.get("reason") == "Unauthorized", (
        f"unexpected /version payload from what should be a genuine k8s API server: {body!r}"
    )

    nodegroups = eks.list_nodegroups(clusterName=cluster_name)["nodegroups"]
    assert nodegroups == []


# ===== helpers =====


def _poll_until(probe, predicate, *, timeout_s: float = 90.0, interval_s: float = 10.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed: {last!r}")


def _tls_probe_k8s_api(ctx, cluster: dict) -> tuple[int | None, dict]:
    try:
        ca_pem = base64.b64decode(cluster["certificateAuthority"]["data"]).decode("ascii")
        ssl_ctx = ssl.create_default_context(cadata=ca_pem)
        endpoint = cluster["endpoint"].rstrip("/")
        target, route = ctx.endpoint_route(endpoint + "/version")
        req = Request(target, method="GET", headers=route)
        with urlopen(req, context=ssl_ctx, timeout=15) as resp:
            return resp.status, json.loads(resp.read())
    except HTTPError as exc:
        return exc.code, json.loads(exc.read())
    except OSError:
        return None, {}


def _retry_delete(fn, attempts: int = 12, delay_s: float = 10.0) -> None:
    last_exc = None
    for _ in range(attempts):
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001 - best-effort cleanup retry
            last_exc = exc
            time.sleep(delay_s)
    if last_exc is not None:
        raise last_exc


def _retry_dependency(fn, release_s: float = 540.0) -> None:
    """Teardown call: retries DependencyViolation while the deleted cluster's ENIs drain; gone is fine."""
    deadline = time.monotonic() + release_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound"):
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _create_vpc_infra(ctx) -> dict:
    ec2 = ctx.client("ec2")

    # Adopt the shared network when the account has one usable -- this is both the
    # cheap path and the one that does not compete for the account's scarce VPC
    # quota. Only a genuinely default-VPC-less account falls through to creating
    # its own, so the check still works there without spending a VPC slot
    # everywhere else.
    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if default_vpcs:
        vpc_id = default_vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
        )["Subnets"]
        subnet_ids = sorted({s["SubnetId"] for s in subnets})
        if len(subnet_ids) >= 2:
            return {"vpc_id": vpc_id, "subnet_ids": subnet_ids[:2], "sg_id": None}

    tag_value = ctx.unique_name("sim2real-eks-cfn-")

    def _tagspec(resource_type: str) -> dict:
        return {
            "ResourceType": resource_type,
            "Tags": [{"Key": "sim2real", "Value": "true"}, {"Key": "Name", "Value": tag_value}],
        }

    vpc_id = ec2.create_vpc(CidrBlock="10.91.0.0/16", TagSpecifications=[_tagspec("vpc")])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    azs = [
        a["ZoneName"]
        for a in ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
            "AvailabilityZones"
        ]
    ][:2]
    if len(azs) < 2:
        raise AssertionError("region does not have at least 2 available AZs for EKS subnets")

    subnet_ids = []
    for i, az in enumerate(azs):
        sid = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.91.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tagspec("subnet")],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=sid: _retry_dependency(lambda: ec2.delete_subnet(SubnetId=sid)))
        subnet_ids.append(sid)

    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "sg_id": None}



def _create_cluster_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-cluster-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        finally:
            iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    return role_arn


def _deploy_stack(ctx, template: dict, parameters: dict, create_timeout_s: float = 1500.0) -> dict:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-eks-stack-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()],
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )

    def _cleanup():
        cfn.delete_stack(StackName=stack_name)
        waiter = cfn.get_waiter("stack_delete_complete")
        waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 540})

    ctx.on_cleanup(_cleanup)

    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": max(10, int(create_timeout_s // 2))})

    outputs = cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("Outputs", [])
    return {"stack_name": stack_name, "outputs": {o["OutputKey"]: o["OutputValue"] for o in outputs}}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
