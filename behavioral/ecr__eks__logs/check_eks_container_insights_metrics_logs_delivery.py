"""eks-container-insights-metrics-logs-delivery."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eks-container-insights-metrics-logs-delivery"
GROUP = "workload-logging"
SERVICES = ["ecr", "eks", "logs"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:e2e", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """The amazon-cloudwatch-observability add-on, with a Pod Identity role carrying
    CloudWatchAgentServerPolicy, delivers events to /aws/containerinsights/<cluster>/performance
    that parse as Embedded Metric Format records naming this cluster."""
    ec2 = ctx.client("ec2")
    eks = ctx.client("eks")

    subnet_ids = _default_vpc_subnets(ctx, ec2)

    _, cluster_role_arn = _create_role(
        ctx,
        "sim2real-ci-clrole-",
        [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        managed_policy_arns=["arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"],
    )
    _, node_role_arn = _create_role(
        ctx,
        "sim2real-ci-noderole-",
        [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        managed_policy_arns=[
            "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
            "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
            "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
        ],
    )
    _, agent_role_arn = _create_role(
        ctx,
        "sim2real-ci-agentrole-",
        [{"Effect": "Allow", "Principal": {"Service": "pods.eks.amazonaws.com"}, "Action": ["sts:AssumeRole", "sts:TagSession"]}],
        managed_policy_arns=["arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"],
    )

    cluster_name = ctx.unique_name("sim2real-ci-")
    _with_role_propagation_retry(
        lambda: eks.create_cluster(
            name=cluster_name,
            roleArn=cluster_role_arn,
            resourcesVpcConfig={"subnetIds": subnet_ids},
            tags={"sim2real-check": CHECK},
        )
    )
    ctx.on_cleanup(lambda: _delete_cluster(eks, cluster_name))
    cluster = _wait_cluster_active(eks, cluster_name)
    k8s_version = cluster["version"]

    ng_name = ctx.unique_name("sim2real-ci-ng-")
    _with_role_propagation_retry(
        lambda: eks.create_nodegroup(
            clusterName=cluster_name,
            nodegroupName=ng_name,
            subnets=subnet_ids,
            nodeRole=node_role_arn,
            scalingConfig={"minSize": 1, "maxSize": 1, "desiredSize": 1},
            instanceTypes=["t3.medium"],
            amiType="AL2023_x86_64_STANDARD",
            tags={"sim2real-check": CHECK},
        )
    )
    ctx.on_cleanup(lambda: _delete_nodegroup(eks, cluster_name, ng_name))
    _wait_nodegroup_active(eks, cluster_name, ng_name)

    eks.create_addon(clusterName=cluster_name, addonName="eks-pod-identity-agent")
    ctx.on_cleanup(lambda: _delete_addon(eks, cluster_name, "eks-pod-identity-agent"))
    _wait_addon_active(eks, cluster_name, "eks-pod-identity-agent")

    _with_role_propagation_retry(
        lambda: eks.create_pod_identity_association(
            clusterName=cluster_name, namespace="amazon-cloudwatch", serviceAccount="cloudwatch-agent", roleArn=agent_role_arn
        )
    )

    classic_version = _pick_classic_addon_version(eks, k8s_version)
    if classic_version is None:
        raise AssertionError(
            "no Classic (v5.x) version of the amazon-cloudwatch-observability add-on is "
            f"available for Kubernetes {k8s_version} in this account/region"
        )
    eks.create_addon(clusterName=cluster_name, addonName="amazon-cloudwatch-observability", addonVersion=classic_version)
    ctx.on_cleanup(lambda: _delete_addon(eks, cluster_name, "amazon-cloudwatch-observability"))
    _wait_addon_active(eks, cluster_name, "amazon-cloudwatch-observability", timeout_s=600.0)

    log_group_name = f"/aws/containerinsights/{cluster_name}/performance"
    events = _poll_performance_events(ctx, log_group_name, timeout_s=900.0)
    assert events, f"no performance log events ever appeared in {log_group_name}"

    parsed_any = False
    for e in events:
        try:
            payload = json.loads(e["message"])
        except (json.JSONDecodeError, ValueError):
            continue
        if "CloudWatchMetrics" in payload and payload.get("ClusterName") == cluster_name:
            parsed_any = True
            break
    assert parsed_any, (
        f"performance log events in {log_group_name} never parsed as EMF records tagged "
        f"with ClusterName={cluster_name!r}"
    )




def _create_role(ctx, name_prefix, trust_statements, managed_policy_arns=()):
    iam = ctx.client("iam")
    name = ctx.unique_name(name_prefix)
    trust = json.dumps({"Version": "2012-10-17", "Statement": trust_statements})
    role_arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=trust, Tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )["Role"]["Arn"]
    for pol in managed_policy_arns:
        iam.attach_role_policy(RoleName=name, PolicyArn=pol)

    def _cleanup():
        for pol in managed_policy_arns:
            try:
                iam.detach_role_policy(RoleName=name, PolicyArn=pol)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return name, role_arn


def _with_role_propagation_retry(fn, timeout_s=90.0, interval_s=5.0):
    """A just-created IAM role is eventually consistent; EKS validates roleArn synchronously
    and rejects a role that has not yet propagated with InvalidParameterException."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as err:
            error = err.response["Error"]
            transient = error["Code"] == "InvalidParameterException" and "role" in error.get("Message", "").lower()
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _default_vpc_subnets(ctx, ec2):
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to host the EKS cluster's subnets")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())
    if len(subnet_ids) < 2:
        raise AssertionError("shared network does not have subnets in >=2 availability zones required by EKS")
    return subnet_ids[:3]


def _wait_cluster_active(eks, name, timeout_s=1500.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = eks.describe_cluster(name=name)["cluster"]
        if desc["status"] == "ACTIVE":
            return desc
        if desc["status"] == "FAILED":
            raise AssertionError(f"cluster {name} entered FAILED status")
        time.sleep(2)
    raise AssertionError(f"cluster {name} did not become ACTIVE within {timeout_s}s")


def _delete_cluster(eks, cluster_name):
    _delete_eks_cluster_retrying(eks, cluster_name)
    deadline = time.monotonic() + 600.0
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=cluster_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        time.sleep(15)


def _wait_nodegroup_active(eks, cluster_name, ng_name, timeout_s=900.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=ng_name)["nodegroup"]
        if desc["status"] == "ACTIVE":
            return desc
        if desc["status"] in ("CREATE_FAILED", "DEGRADED"):
            raise AssertionError(f"nodegroup {ng_name} entered {desc['status']}")
        time.sleep(2)
    raise AssertionError(f"nodegroup {ng_name} did not become ACTIVE within {timeout_s}s")


def _delete_nodegroup(eks, cluster_name, ng_name):
    try:
        eks.delete_nodegroup(clusterName=cluster_name, nodegroupName=ng_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    deadline = time.monotonic() + 600.0
    while time.monotonic() < deadline:
        try:
            eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=ng_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        time.sleep(15)


def _wait_addon_active(eks, cluster_name, addon_name, timeout_s=600.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = eks.describe_addon(clusterName=cluster_name, addonName=addon_name)["addon"]["status"]
        if status == "ACTIVE":
            return
        if status in ("CREATE_FAILED", "DEGRADED"):
            raise AssertionError(f"addon {addon_name} entered {status}")
        time.sleep(2)
    raise AssertionError(f"addon {addon_name} did not become ACTIVE within {timeout_s}s")


def _delete_addon(eks, cluster_name, addon_name):
    try:
        eks.delete_addon(clusterName=cluster_name, addonName=addon_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    deadline = time.monotonic() + 300.0
    while time.monotonic() < deadline:
        try:
            eks.describe_addon(clusterName=cluster_name, addonName=addon_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        time.sleep(10)


def _pick_classic_addon_version(eks, k8s_version):
    resp = eks.describe_addon_versions(addonName="amazon-cloudwatch-observability", kubernetesVersion=k8s_version)
    addons = resp.get("addons", [])
    if not addons:
        return None
    versions = [v["addonVersion"] for v in addons[0].get("addonVersions", [])]
    classic = sorted((v for v in versions if v.startswith("v5.")), reverse=True)
    return classic[0] if classic else None


def _poll_performance_events(ctx, log_group_name, timeout_s=900.0, interval_s=20.0):
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = logs.filter_log_events(logGroupName=log_group_name, limit=20)
            events = resp.get("events", [])
            if events:
                return events
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(interval_s)
    return []



def _delete_eks_cluster_retrying(eks, name, timeout_s=900.0, interval_s=20.0):
    """DeleteCluster, retried while EKS refuses it because an update or child resource is in flight."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return eks.delete_cluster(name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return None
            if e.response["Error"]["Code"] != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
