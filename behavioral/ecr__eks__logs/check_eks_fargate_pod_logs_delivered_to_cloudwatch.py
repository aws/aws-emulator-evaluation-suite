"""eks-fargate-pod-logs-delivered-to-cloudwatch."""

from __future__ import annotations

import base64
import json
import tempfile
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eks-fargate-pod-logs-delivered-to-cloudwatch"
GROUP = "workload-logging"
SERVICES = ["ecr", "eks", "logs"]


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "concern:metrics",
    "dp:api",
    "dp:native",
    "plane:data",
)
def run(ctx) -> None:
    """A Fargate pod's stdout, routed through the built-in Fluent Bit log router
    configured via the aws-logging ConfigMap (awslogs/cloudwatch_logs destination),
    is actually delivered into the CloudWatch Logs group named in that ConfigMap."""
    import kubernetes  # noqa: F401 - a runner without it raises ImportError, not a finding

    ec2 = ctx.client("ec2")
    eks = ctx.client("eks")

    private_subnet_ids = _create_private_networking(ctx, ec2)

    _, cluster_role_arn = _create_role(
        ctx,
        "sim2real-fglog-clrole-",
        [
            {
                "Effect": "Allow",
                "Principal": {"Service": "eks.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
        managed_policy_arns=["arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"],
    )
    _, pod_exec_role_arn = _create_role(
        ctx,
        "sim2real-fglog-podexec-",
        [
            {
                "Effect": "Allow",
                "Principal": {"Service": "eks-fargate-pods.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
        managed_policy_arns=[
            "arn:aws:iam::aws:policy/AmazonEKSFargatePodExecutionRolePolicy"
        ],
        inline_policy_document={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "logs:CreateLogStream",
                        "logs:CreateLogGroup",
                        "logs:DescribeLogStreams",
                        "logs:PutLogEvents",
                    ],
                    "Resource": "*",
                }
            ],
        },
    )

    cluster_name = ctx.unique_name("sim2real-fglog-")
    eks.create_cluster(
        name=cluster_name,
        roleArn=cluster_role_arn,
        resourcesVpcConfig={"subnetIds": private_subnet_ids},
        tags={"Name": cluster_name},
    )
    ctx.on_cleanup(lambda: _delete_cluster(eks, cluster_name))
    cluster = _wait_cluster_active(eks, cluster_name, timeout_s=_budget_s(ctx, 1500.0), ctx=ctx)

    profile_name = ctx.unique_name("sim2real-fp-")
    eks.create_fargate_profile(
        fargateProfileName=profile_name,
        clusterName=cluster_name,
        podExecutionRoleArn=pod_exec_role_arn,
        subnets=private_subnet_ids,
        selectors=[{"namespace": "default"}],
        tags={"Name": profile_name},
    )
    ctx.on_cleanup(lambda: _delete_fargate_profile(eks, cluster_name, profile_name))
    _wait_fargate_profile_active(eks, cluster_name, profile_name, timeout_s=_budget_s(ctx, 600.0),
                                 ctx=ctx)

    log_group_name = ctx.unique_name("sim2real-fargate-logs-")
    ctx.on_cleanup(
        lambda: _safe_call(
            lambda: ctx.client("logs").delete_log_group(logGroupName=log_group_name)
        )
    )

    core_v1 = _k8s_core_v1(ctx, cluster, cluster_name)
    _create_aws_observability_namespace(core_v1)
    output_conf = (
        "[OUTPUT]\n"
        "    Name cloudwatch_logs\n"
        "    Match kube.*\n"
        f"    region {ctx.region}\n"
        f"    log_group_name {log_group_name}\n"
        "    log_stream_prefix from-fluent-bit-\n"
        "    auto_create_group true\n"
    )
    _create_aws_logging_configmap(core_v1, output_conf)

    marker = ctx.unique_name("sim2real-marker-")
    pod_name = ctx.unique_name("sim2real-pod-")
    _create_echo_pod(core_v1, "default", pod_name, marker)
    ctx.on_cleanup(lambda: _delete_pod(ctx, cluster, cluster_name, "default", pod_name))

    phase = _wait_pod_phase(
        ctx,
        cluster,
        cluster_name,
        "default",
        pod_name,
        lambda p: p in {"Running", "Succeeded"},
        timeout_s=_budget_s(ctx, 420.0),
    )
    if phase not in {"Running", "Succeeded"} and _budget_spent(ctx):
        raise TimeoutError(f"pod {pod_name} leaving Pending: the run budget ended first; not graded")
    assert phase in {"Running", "Succeeded"}, (
        f"pod {pod_name} never left Pending (phase={phase!r})"
    )

    events = _poll_log_events(ctx, log_group_name, marker, timeout_s=_budget_s(ctx, 600.0))
    if not events and _budget_spent(ctx):
        raise TimeoutError(
            f"marker {marker!r} in log group {log_group_name}: the run budget ended first; not graded")
    assert events, f"marker {marker!r} never appeared in log group {log_group_name}"
    assert any(marker in e["message"] for e in events), (
        f"marker {marker!r} not present in any of {len(events)} log event(s) fetched from "
        f"{log_group_name}: {[e.get('message') for e in events][:5]!r}"
    )



def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0

def _safe_call(fn) -> None:
    """Run a teardown step; only the resource's own not-found counts as done."""
    try:
        fn()
    except Exception as exc:
        if not _not_found(exc):
            raise


def _tag_spec(resource_type: str, name: str) -> dict[str, Any]:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _safe_delete(fn, timeout_s: float = 90.0) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as err:
            if _not_found(err):
                return
            code = err.response["Error"]["Code"]
            if (
                code in ("DependencyViolation", "InvalidParameterValue")
                and time.monotonic() < deadline
            ):
                time.sleep(2)
                continue
            raise RuntimeError(f"network resource was not deleted: {err!r}") from err


def _create_role(
    ctx,
    name_prefix,
    trust_statements,
    managed_policy_arns=(),
    inline_policy_document=None,
):
    iam = ctx.client("iam")
    name = ctx.unique_name(name_prefix)
    trust = json.dumps({"Version": "2012-10-17", "Statement": trust_statements})
    role_arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust)["Role"][
        "Arn"
    ]
    for pol in managed_policy_arns:
        iam.attach_role_policy(RoleName=name, PolicyArn=pol)
    if inline_policy_document is not None:
        iam.put_role_policy(
            RoleName=name,
            PolicyName="inline",
            PolicyDocument=json.dumps(inline_policy_document),
        )

    def _cleanup():
        if inline_policy_document is not None:
            _safe_call(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
        for pol in managed_policy_arns:
            _safe_call(lambda pol=pol: iam.detach_role_policy(RoleName=name, PolicyArn=pol))
        _safe_call(lambda: iam.delete_role(RoleName=name))

    ctx.on_cleanup(_cleanup)

    def _visible() -> bool:
        try:
            attached = {
                p["PolicyArn"]
                for p in iam.list_attached_role_policies(RoleName=name)[
                    "AttachedPolicies"
                ]
            }
        except ClientError:
            return False
        if not set(managed_policy_arns) <= attached:
            return False
        if inline_policy_document is not None:
            try:
                iam.get_role_policy(RoleName=name, PolicyName="inline")
            except ClientError:
                return False
        return True

    wait_s = _budget_s(ctx, 90.0)
    deadline = time.monotonic() + wait_s
    while time.monotonic() < deadline:
        if _visible():
            break
        time.sleep(1)
    else:
        if _budget_spent(ctx):
            raise TimeoutError(
                f"role {name}'s policies becoming visible: the run budget ended first; not graded")
        raise AssertionError(
            f"role {name}'s attached/inline policies never became visible via IAM's own reads "
            f"within {wait_s:.0f}s"
        )
    return name, role_arn


def _create_private_networking(ctx, ec2):
    """Build a minimal VPC with 2 private (NAT-routed) subnets - required by Fargate profiles."""
    name = ctx.unique_name("sim2real-fgnet-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.61.0.0/16", TagSpecifications=[_tag_spec("vpc", name)]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[_tag_spec("internet-gateway", name)]
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    def _detach_delete_igw():
        _safe_delete(
            lambda: _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id)
        )
        _safe_delete(lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id))

    ctx.on_cleanup(_detach_delete_igw)

    azs = [
        a["ZoneName"]
        for a in ec2.describe_availability_zones()["AvailabilityZones"][:2]
    ]
    public_subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.61.0.0/24",
        AvailabilityZone=azs[0],
        TagSpecifications=[_tag_spec("subnet", f"{name}-pub")],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(
        lambda: _safe_delete(lambda: _delete_net(ec2, "delete_subnet", SubnetId=public_subnet_id))
    )

    private_subnet_ids = []
    for i, az in enumerate(azs):
        sid = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.61.{i + 1}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tag_spec("subnet", f"{name}-priv-{i}")],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(
            lambda sid=sid: _safe_delete(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        )
        private_subnet_ids.append(sid)

    eip_alloc = ec2.allocate_address(
        Domain="vpc", TagSpecifications=[_tag_spec("elastic-ip", name)]
    )["AllocationId"]
    ctx.on_cleanup(
        lambda: _safe_delete(lambda: ec2.release_address(AllocationId=eip_alloc))
    )

    nat_gw_id = ec2.create_nat_gateway(
        SubnetId=public_subnet_id,
        AllocationId=eip_alloc,
        TagSpecifications=[_tag_spec("natgateway", name)],
    )["NatGateway"]["NatGatewayId"]
    ctx.on_cleanup(lambda: _delete_nat_gateway(ec2, nat_gw_id))
    ec2.get_waiter("nat_gateway_available").wait(NatGatewayIds=[nat_gw_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    public_rt_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=[_tag_spec("route-table", f"{name}-pub")]
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(
        lambda: _safe_delete(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=public_rt_id))
    )
    ec2.create_route(
        RouteTableId=public_rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id
    )
    assoc_pub = ec2.associate_route_table(
        RouteTableId=public_rt_id, SubnetId=public_subnet_id
    )["AssociationId"]
    ctx.on_cleanup(
        lambda: _safe_delete(
            lambda: ec2.disassociate_route_table(AssociationId=assoc_pub)
        )
    )

    private_rt_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=[_tag_spec("route-table", f"{name}-priv")]
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(
        lambda: _safe_delete(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=private_rt_id))
    )
    ec2.create_route(
        RouteTableId=private_rt_id,
        DestinationCidrBlock="0.0.0.0/0",
        NatGatewayId=nat_gw_id,
    )
    for sid in private_subnet_ids:
        assoc_id = ec2.associate_route_table(RouteTableId=private_rt_id, SubnetId=sid)[
            "AssociationId"
        ]
        ctx.on_cleanup(
            lambda assoc_id=assoc_id: _safe_delete(
                lambda: ec2.disassociate_route_table(AssociationId=assoc_id)
            )
        )

    return private_subnet_ids


def _delete_nat_gateway(ec2, nat_gw_id):
    try:
        ec2.delete_nat_gateway(NatGatewayId=nat_gw_id)
    except Exception as exc:
        if _not_found(exc):
            return
        raise RuntimeError(f"NAT gateway {nat_gw_id} was not deleted: {exc!r}") from exc
    last = None
    deadline = time.monotonic() + 300.0
    while time.monotonic() < deadline:
        try:
            state = ec2.describe_nat_gateways(NatGatewayIds=[nat_gw_id])["NatGateways"][
                0
            ]["State"]
        except Exception as exc:
            if _not_found(exc):
                return
            last = exc
        else:
            if state == "deleted":
                return
            last = state
        time.sleep(2)
    raise RuntimeError(f"NAT gateway {nat_gw_id} was not deleted: {last!r}")


def _wait_cluster_active(eks, name, timeout_s=1500.0, ctx=None):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = eks.describe_cluster(name=name)["cluster"]
        if desc["status"] == "ACTIVE":
            return desc
        if desc["status"] == "FAILED":
            raise AssertionError(f"cluster {name} entered FAILED status")
        time.sleep(2)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"cluster {name} becoming ACTIVE: the run budget ended first; not graded")
    raise AssertionError(f"cluster {name} did not become ACTIVE within {timeout_s}s")


def _wait_fargate_profile_active(eks, cluster_name, profile_name, timeout_s=600.0, ctx=None):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = eks.describe_fargate_profile(
            clusterName=cluster_name, fargateProfileName=profile_name
        )["fargateProfile"]
        if desc["status"] == "ACTIVE":
            return desc
        if desc["status"] == "CREATE_FAILED":
            raise AssertionError(
                f"fargate profile {profile_name} entered CREATE_FAILED"
            )
        time.sleep(2)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(
            f"fargate profile {profile_name} becoming ACTIVE: the run budget ended first; not graded")
    raise AssertionError(
        f"fargate profile {profile_name} did not become ACTIVE within {timeout_s}s"
    )


def _not_found(exc) -> bool:
    """The resource is already gone: its service's own not-found code."""
    code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
    return "NotFound" in code or code == "NoSuchEntity"


def _delete_fargate_profile(eks, cluster_name, profile_name):
    try:
        eks.delete_fargate_profile(
            clusterName=cluster_name, fargateProfileName=profile_name
        )
    except Exception as exc:
        if _not_found(exc):
            return
        raise RuntimeError(f"fargate profile {profile_name} was not deleted: {exc!r}") from exc
    last = "still described"
    deadline = time.monotonic() + 600.0
    while time.monotonic() < deadline:
        try:
            eks.describe_fargate_profile(
                clusterName=cluster_name, fargateProfileName=profile_name
            )
        except Exception as exc:
            if _not_found(exc):
                return
            last = exc
        time.sleep(2)
    raise RuntimeError(f"fargate profile {profile_name} was not deleted: {last!r}")


def _delete_cluster(eks, cluster_name):
    try:
        eks.delete_cluster(name=cluster_name)
    except Exception as exc:
        if _not_found(exc):
            return
        raise RuntimeError(f"EKS cluster {cluster_name} was not deleted: {exc!r}") from exc
    last = "still described"
    deadline = time.monotonic() + 600.0
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=cluster_name)
        except Exception as exc:
            if _not_found(exc):
                return
            last = exc
        time.sleep(2)
    raise RuntimeError(f"EKS cluster {cluster_name} was not deleted: {last!r}")


def _eks_bearer_token(ctx, cluster_name):
    """k8s-aws-v1.<base64url of a presigned STS GetCallerIdentity URL signing x-k8s-aws-id>.

    Signed through ctx's STS client so it uses the run's credentials. The hooks are unregistered
    before returning because that client is cached; a repeat header would make the API server 401."""
    sts = ctx.client("sts", endpoint_url=ctx.service_url(f"https://sts.{ctx.region}.amazonaws.com"))

    def _capture(params=None, context=None, **_kwargs):
        if params is not None and context is not None and "ClusterName" in params:
            context["eks_cluster"] = params.pop("ClusterName")

    def _inject(request=None, **_kwargs):
        name = (getattr(request, "context", None) or {}).get("eks_cluster")
        if name:
            if "x-k8s-aws-id" in request.headers:
                del request.headers["x-k8s-aws-id"]
            request.headers["x-k8s-aws-id"] = name

    sts.meta.events.register("provide-client-params.sts.GetCallerIdentity", _capture)
    sts.meta.events.register("before-sign.sts.GetCallerIdentity", _inject)
    try:
        url = sts.generate_presigned_url(
            "get_caller_identity",
            Params={"ClusterName": cluster_name},
            ExpiresIn=60,
            HttpMethod="GET",
        )
    finally:
        sts.meta.events.unregister(
            "provide-client-params.sts.GetCallerIdentity", _capture
        )
        sts.meta.events.unregister("before-sign.sts.GetCallerIdentity", _inject)
    return "k8s-aws-v1." + base64.urlsafe_b64encode(url.encode("utf-8")).decode(
        "ascii"
    ).rstrip("=")


def _k8s_core_v1(ctx, cluster, cluster_name):
    from kubernetes import client as k8s_client

    ca_file = tempfile.NamedTemporaryFile(delete=False, suffix=".crt")
    ca_file.write(base64.b64decode(cluster["certificateAuthority"]["data"]))
    # The API server's certificate is signed by the cluster CA, so that CA stays pinned; a
    # ctx.http_verify bundle is trusted beside it, and False turns verification off.
    if isinstance(ctx.http_verify, str):
        with open(ctx.http_verify, "rb") as bundle:
            ca_file.write(b"\n" + bundle.read())
    ca_file.close()
    host, route = ctx.endpoint_route(cluster["endpoint"])
    configuration = k8s_client.Configuration()
    configuration.host = host
    configuration.ssl_ca_cert = ca_file.name
    configuration.verify_ssl = ctx.http_verify is not False
    configuration.api_key = {
        "authorization": "Bearer " + _eks_bearer_token(ctx, cluster_name)
    }
    api_client = k8s_client.ApiClient(configuration)
    for name, value in route.items():
        api_client.set_default_header(name, value)
    return k8s_client.CoreV1Api(api_client)


def _create_aws_observability_namespace(core_v1) -> None:
    body = {
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {
            "name": "aws-observability",
            "labels": {"aws-observability": "enabled"},
        },
    }
    core_v1.create_namespace(body)


def _create_aws_logging_configmap(core_v1, output_conf: str) -> None:
    body = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": "aws-logging", "namespace": "aws-observability"},
        "data": {"output.conf": output_conf},
    }
    core_v1.create_namespaced_config_map("aws-observability", body)


def _create_echo_pod(core_v1, namespace: str, pod_name: str, marker: str) -> None:
    body: dict[str, Any] = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": pod_name, "namespace": namespace},
        "spec": {
            "restartPolicy": "Never",
            "containers": [
                {
                    "name": "test",
                    "image": "public.ecr.aws/docker/library/busybox:1.36",
                    "command": ["sh", "-c", f"echo {marker}; sleep 900"],
                }
            ],
        },
    }
    core_v1.create_namespaced_pod(namespace, body)


def _delete_pod(ctx, cluster, cluster_name, namespace, pod_name):
    from kubernetes.client.exceptions import ApiException

    core_v1 = _k8s_core_v1(ctx, cluster, cluster_name)
    try:
        core_v1.delete_namespaced_pod(pod_name, namespace, grace_period_seconds=0)
    except ApiException as exc:
        if exc.status != 404:
            raise


def _wait_pod_phase(
    ctx, cluster, cluster_name, namespace, pod_name, predicate, timeout_s=420.0
):
    deadline = time.monotonic() + timeout_s
    last = ""
    while time.monotonic() < deadline:
        core_v1 = _k8s_core_v1(ctx, cluster, cluster_name)
        try:
            last = core_v1.read_namespaced_pod(pod_name, namespace).status.phase or ""
        except Exception:
            last = ""
        if predicate(last):
            return last
        time.sleep(2)
    return last


def _poll_log_events(ctx, log_group_name, marker, timeout_s=600.0, interval_s=2.0):
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = logs.filter_log_events(
                logGroupName=log_group_name, filterPattern=f'"{marker}"'
            )
            events = resp.get("events", [])
            if events:
                return events
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(interval_s)
    return []


# Resources in the VPC delete asynchronously and leave their ENIs behind for a while, so an
# immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. Wait
# (bounded, shared by all of one check's network deletes) for the ENIs to go, retry, then raise
# naming the ENIs still attached.
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
