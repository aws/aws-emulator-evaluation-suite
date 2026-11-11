"""eks-pod-ip-is-a-secondary-address-on-a-real-vpc-eni."""
from __future__ import annotations

import base64
import ipaddress
import json
import re
import ssl
import time
import urllib.error
import urllib.request

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "eks-pod-ip-is-a-secondary-address-on-a-real-vpc-eni"
GROUP = 'data-plane'
SERVICES = ['eks']

_CLUSTER_ROLE_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
_NODE_POLICIES = (
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
)
_BAD_AZS = {"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"}
_NODE_TYPE = "t3.medium"
_FIXTURE_TAGS = {"sim2real:managed": "true", "sim2real": "b3-eks-workloads"}

# CreateCluster reaches ACTIVE in ~7 min, CreateNodegroup in ~2 min, and a busybox pod runs with
# an IP within seconds of POST. The budgets below are ~2x margins.
_CLUSTER_TIMEOUT_S = 800
_CLUSTER_DELETE_TIMEOUT_S = 500
_NODEGROUP_TIMEOUT_S = 500
_NODEGROUP_DELETE_TIMEOUT_S = 500
_DELETE_RETRY_TIMEOUT_S = 240
_POD_TIMEOUT_S = 300
_NS_DELETE_TIMEOUT_S = 240
# The window over which the released address is observed. The VPC CNI's warm pool keeps the
# deleted pod's address for minutes, so this is a bound on the OBSERVATION, not a wait for a
# change that never comes.
_RELEASE_OBSERVE_S = 120

_IMAGE = "public.ecr.aws/docker/library/busybox:1.36"
_PROVIDER_ID_RE = re.compile(r"^aws:///[a-z0-9-]+/(i-[0-9a-f]+)$")
# The VPC CNI names every ENI it attaches after the instance it attached it to.
_CNI_ENI_DESC_PREFIX = "aws-K8S-"
# t3.medium: 3 ENIs x 6 IPv4 each, minus the node's own primary, so kubelet advertises 17.
# The bound is deliberately wide enough to survive an ENI-limit revision but narrow enough that an
# emulator reporting unbounded pod capacity fails.
_ALLOCATABLE_PODS_MIN = 8
_ALLOCATABLE_PODS_MAX = 110


def _wait_for(fn, pred, *, timeout_s, interval_s, desc):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for {desc}; last={val!r}"
            )
        time.sleep(interval_s)
        val = fn()
    return val


def _trust(service):
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": service},
                       "Action": ["sts:AssumeRole"]}],
    })


def _create_role(ctx, name, service, managed_policies=()):
    iam = ctx.client("iam")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_trust(service),
        Description="sim2real b3-eks-workloads pod-ip check",
        Tags=[{"Key": k, "Value": v} for k, v in _FIXTURE_TAGS.items()],
    )["Role"]["Arn"]
    for policy_arn in managed_policies:
        iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
    return arn


def _delete_role(iam, name):
    try:
        for pol in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=name, PolicyName=pol)
        for pol in iam.list_attached_role_policies(RoleName=name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=name, PolicyArn=pol["PolicyArn"])
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _fixture_subnets(ctx):
    """Default-VPC subnets in EKS-supported AZs that also offer the node instance type."""
    ec2 = ctx.client("ec2")
    offered = {
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [_NODE_TYPE]}, {"Name": "location", "Values": ctx.network().availability_zones}],
        )["InstanceTypeOfferings"]
    }
    usable = {
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}]
        )["AvailabilityZones"]
        if z["ZoneName"] in offered and z["ZoneId"] not in _BAD_AZS
    }
    assert usable, (
        f"no available AZ in {ctx.region} offers {_NODE_TYPE!r}; offerings were "
        f"{sorted(offered)!r}"
    )
    by_az = {}
    for sn in sorted(
        ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"],
        key=lambda s: s["AvailabilityZone"],
    ):
        if sn["AvailabilityZone"] in usable:
            by_az.setdefault(sn["AvailabilityZone"], sn["SubnetId"])
    assert len(by_az) >= 2, (
        f"EKS needs subnets in >=2 supported AZs; the run's shared network offers {sorted(by_az)!r}"
    )
    return [by_az[az] for az in sorted(by_az)][:3]


def _cluster_status(c, name):
    try:
        return c.describe_cluster(name=name)["cluster"]["status"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return "GONE"
        raise


def _nodegroup_status(c, cluster, ng):
    try:
        return c.describe_nodegroup(clusterName=cluster, nodegroupName=ng)["nodegroup"]["status"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return "GONE"
        raise


def _create_cluster(ctx, name, role_arn):
    c = ctx.client("eks")
    deadline = time.monotonic() + _DELETE_RETRY_TIMEOUT_S
    while True:
        try:
            c.create_cluster(
                name=name,
                roleArn=role_arn,
                resourcesVpcConfig={
                    "subnetIds": _fixture_subnets(ctx),
                    "endpointPublicAccess": True,
                    "endpointPrivateAccess": False,
                },
                accessConfig={
                    "authenticationMode": "API_AND_CONFIG_MAP",
                    "bootstrapClusterCreatorAdminPermissions": True,
                },
                tags=dict(_FIXTURE_TAGS),
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterException":
                raise
            assert time.monotonic() < deadline, (
                f"CreateCluster kept rejecting the cluster role {role_arn!r} for "
                f"{_DELETE_RETRY_TIMEOUT_S}s: {exc}"
            )
            time.sleep(2)
    cluster = _wait_for(
        lambda: c.describe_cluster(name=name)["cluster"],
        lambda cl: cl["status"] in ("ACTIVE", "FAILED"),
        timeout_s=_CLUSTER_TIMEOUT_S,
        interval_s=20,
        desc=f"cluster {name} ACTIVE",
    )
    assert cluster["status"] == "ACTIVE", (
        f"cluster {name!r} landed in {cluster['status']!r}; health={cluster.get('health')!r}"
    )
    return cluster


def _create_nodegroup(ctx, cluster_name, ng, node_role_arn):
    c = ctx.client("eks")
    deadline = time.monotonic() + _DELETE_RETRY_TIMEOUT_S
    while True:
        try:
            c.create_nodegroup(
                clusterName=cluster_name,
                nodegroupName=ng,
                subnets=_fixture_subnets(ctx),
                nodeRole=node_role_arn,
                scalingConfig={"minSize": 1, "maxSize": 1, "desiredSize": 1},
                instanceTypes=[_NODE_TYPE],
                amiType="AL2023_x86_64_STANDARD",
                capacityType="ON_DEMAND",
                diskSize=20,
                tags=dict(_FIXTURE_TAGS),
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterException":
                raise
            # IAM is eventually consistent and exposes no condition to poll; EKS rejects a
            # brand-new node role with InvalidParameterException until it propagates.
            assert time.monotonic() < deadline, (
                f"CreateNodegroup kept rejecting the node role {node_role_arn!r} for "
                f"{_DELETE_RETRY_TIMEOUT_S}s: {exc}"
            )
            time.sleep(2)
    status = _wait_for(
        lambda: _nodegroup_status(c, cluster_name, ng),
        lambda s: s in ("ACTIVE", "CREATE_FAILED", "DEGRADED"),
        timeout_s=_NODEGROUP_TIMEOUT_S,
        interval_s=20,
        desc=f"nodegroup {ng} ACTIVE",
    )
    assert status == "ACTIVE", f"node group {ng!r} landed in {status!r}"


def _delete_with_retry(fn, desc):
    deadline = time.monotonic() + _DELETE_RETRY_TIMEOUT_S
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException":
                raise
            assert time.monotonic() < deadline, (
                f"{desc} was still refused with ResourceInUseException after "
                f"{_DELETE_RETRY_TIMEOUT_S}s: {exc}"
            )
            time.sleep(2)


def _teardown_nodegroup(c, cluster, ng):
    _delete_with_retry(
        lambda: c.delete_nodegroup(clusterName=cluster, nodegroupName=ng),
        f"delete nodegroup {ng}",
    )
    _wait_for(
        lambda: _nodegroup_status(c, cluster, ng),
        lambda s: s == "GONE",
        timeout_s=_NODEGROUP_DELETE_TIMEOUT_S,
        interval_s=20,
        desc=f"nodegroup {ng} deleted",
    )


def _teardown_cluster(c, name):
    """Drain the node group, delete the control plane, poll until both are actually gone.

    Called inline from run()'s `finally`, because ctx.on_cleanup's 60 s budget cannot cover it."""
    try:
        for ng in c.list_nodegroups(clusterName=name).get("nodegroups", []):
            _teardown_nodegroup(c, name, ng)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    _delete_with_retry(lambda: c.delete_cluster(name=name), f"delete cluster {name}")
    _wait_for(
        lambda: _cluster_status(c, name),
        lambda s: s == "GONE",
        timeout_s=_CLUSTER_DELETE_TIMEOUT_S,
        interval_s=20,
        desc=f"cluster {name} fully deleted",
    )


def _k8s_token(ctx, cluster_name, *, ttl_s=900):
    """Mint the EKS Kubernetes bearer token for the current caller (k8s-aws-v1 scheme).

    A FRESH sts client every call: ``add_header`` APPENDS, so a cached client would sign a
    duplicated ``x-k8s-aws-id`` and get 401."""
    # A client of its own per cluster, so the signed x-k8s-aws-id header never reaches other calls.
    sts = ctx.client(
        "sts",
        endpoint_url=ctx.service_url(f"https://sts.{ctx.region}.amazonaws.com"),
        config=Config(user_agent_extra=f"k8s-aws-id/{cluster_name}"),
    )
    sts.meta.events.register(
        "before-sign.sts.GetCallerIdentity",
        lambda request, **kwargs: request.headers.add_header("x-k8s-aws-id", cluster_name),
        unique_id=f"k8s-aws-id/{cluster_name}",
    )
    url = sts.generate_presigned_url(
        "get_caller_identity", Params={}, ExpiresIn=ttl_s, HttpMethod="GET"
    )
    return "k8s-aws-v1." + base64.urlsafe_b64encode(url.encode("utf-8")).decode(
        "utf-8"
    ).rstrip("=")


def _k8s(ctx, conn, method, path, *, body=None, timeout_s=60):
    """Request the cluster's Kubernetes API server, trusting ONLY the advertised CA."""
    base, ca_pem, name = conn
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_ctx.check_hostname = True
    ssl_ctx.verify_mode = ssl.CERT_REQUIRED
    ssl_ctx.load_verify_locations(cadata=ca_pem)
    headers = {"Accept": "application/json",
               "Authorization": f"Bearer {_k8s_token(ctx, name)}"}
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = _routed_request(ctx,
        base.rstrip("/") + path, method=method, data=data, headers=headers
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s, context=ssl_ctx) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _k8s_json(ctx, conn, method, path, *, body=None, expect=(200, 201)):
    status, raw = _k8s(ctx, conn, method, path, body=body)
    assert status in expect, (
        f"{method} {path} on the Kubernetes API returned {status}, expected one of {expect}: "
        f"{raw[:400]!r}"
    )
    return json.loads(raw)


def _instance_enis(ec2, instance_id):
    """Every ENI attached to the instance, paginated."""
    out = []
    for page in ec2.get_paginator("describe_network_interfaces").paginate(
        Filters=[{"Name": "attachment.instance-id", "Values": [instance_id]}]
    ):
        out.extend(page["NetworkInterfaces"])
    return out


def _eni_addresses(enis):
    """{private ip -> (eni id, Primary flag)} across a set of ENIs."""
    out = {}
    for eni in enis:
        for addr in eni["PrivateIpAddresses"]:
            out[addr["PrivateIpAddress"]] = (eni["NetworkInterfaceId"], addr["Primary"])
    return out


def _claimed_pod_ips(ctx, conn):
    """Every podIP any pod in the whole cluster currently claims, paginated on `continue`."""
    ips = set()
    token = ""
    while True:
        path = "/api/v1/pods?limit=200" + (f"&continue={token}" if token else "")
        page = _k8s_json(ctx, conn, "GET", path)
        for pod in page["items"]:
            if pod["status"].get("podIP"):
                ips.add(pod["status"]["podIP"])
        token = page["metadata"].get("continue") or ""
        if not token:
            return ips


def _sleeper(pod, node_name):
    return {
        "apiVersion": "v1", "kind": "Pod", "metadata": {"name": pod},
        "spec": {
            "restartPolicy": "Never",
            # Pinned to one node on purpose: assertion (8) is that TWO pods on the SAME instance
            # get two distinct secondary addresses on that instance's ENIs.
            "nodeName": node_name,
            "containers": [{"name": "s", "image": _IMAGE,
                            "command": ["sh", "-c", "sleep 600"]}],
        },
    }


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:representation",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An EKS pod's podIP is a secondary private address on an ENI of its node's instance, inside
    that ENI's subnet CIDR and distinct per pod; a deleted pod's address stays in the CNI warm pool
    on the ENI while no pod claims it.

    Reference: https://docs.aws.amazon.com/eks/latest/userguide/managing-vpc-cni.html
    """
    eks = ctx.client("eks")
    iam = ctx.client("iam")
    ec2 = ctx.client("ec2")
    suffix = ctx.unique_name("")[:8]
    cluster_name = f"sim2real-b3-podip-{suffix}"
    nodegroup = "podip-ng"
    cluster_role = f"sim2real-b3-podip-cr-{suffix}"
    node_role = f"sim2real-b3-podip-nr-{suffix}"
    ns = f"sim2real-b3-podip-{suffix}"
    pod_a, pod_b = "sim2real-podip-a", "sim2real-podip-b"
    body_failed = []

    cluster_role_arn = _create_role(ctx, cluster_role, "eks.amazonaws.com",
                                    [_CLUSTER_ROLE_POLICY])
    ctx.on_cleanup(lambda: _delete_role(iam, cluster_role))
    node_role_arn = _create_role(ctx, node_role, "ec2.amazonaws.com", _NODE_POLICIES)
    ctx.on_cleanup(lambda: _delete_role(iam, node_role))

    cluster = _create_cluster(ctx, cluster_name, cluster_role_arn)
    ctx.on_cleanup(lambda: _teardown_cluster(eks, cluster_name))
    ca_pem = base64.b64decode(cluster["certificateAuthority"]["data"]).decode("ascii")
    assert ca_pem.startswith("-----BEGIN CERTIFICATE-----"), (
        f"certificateAuthority.data did not decode to a PEM certificate: {ca_pem[:60]!r}"
    )
    conn = (cluster["endpoint"], ca_pem, cluster_name)

    # Torn down inline in `finally`, children before parents: ctx.on_cleanup's 60 s budget would
    # cut an EKS delete off and leak a billable control plane.
    try:
        _create_nodegroup(ctx, cluster_name, nodegroup, node_role_arn)
        node = _wait_for(
            lambda: _k8s_json(ctx, conn, "GET", "/api/v1/nodes")["items"],
            lambda items: len(items) == 1 and any(
                cond["type"] == "Ready" and cond["status"] == "True"
                for cond in items[0]["status"]["conditions"]
            ),
            timeout_s=_NODEGROUP_TIMEOUT_S,
            interval_s=10,
            desc="exactly one Ready Node object",
        )[0]
        node_name = node["metadata"]["name"]

        # (1) The Kubernetes Node names its own EC2 instance, in the documented providerID form.
        provider_id = node["spec"]["providerID"]
        matched = _PROVIDER_ID_RE.match(provider_id)
        assert matched, (
            f"Node.spec.providerID is {provider_id!r}, which is not the aws:///<az>/<instance-id> "
            f"form every AWS cloud-provider integration writes"
        )
        instance_id = matched.group(1)
        reservations = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
        instance = reservations[0]["Instances"][0]
        assert instance["State"]["Name"] == "running", (
            f"the instance {instance_id!r} the Node names is {instance['State']['Name']!r}"
        )

        # (2) The Node object and the EKS node group are the same compute.
        inst_tags = {t["Key"]: t["Value"] for t in instance["Tags"]}
        assert inst_tags.get("eks:nodegroup-name") == nodegroup, (
            f"the instance behind Node {node_name!r} carries eks:nodegroup-name "
            f"{inst_tags.get('eks:nodegroup-name')!r}, not {nodegroup!r}; tags were "
            f"{sorted(inst_tags)!r}"
        )
        assert inst_tags.get("eks:cluster-name") == cluster_name, (
            f"the instance's eks:cluster-name is {inst_tags.get('eks:cluster-name')!r}, not "
            f"{cluster_name!r}"
        )

        node_internal_ip = [
            a["address"] for a in node["status"]["addresses"] if a["type"] == "InternalIP"
        ]
        assert len(node_internal_ip) == 1, (
            f"the Node reports {node_internal_ip!r} InternalIP addresses, expected exactly one"
        )
        node_internal_ip = node_internal_ip[0]

        # (3) The kubelet advertises a pod capacity bounded by the instance type's ENI x IP limit,
        #     not an unbounded one.
        allocatable_pods = int(node["status"]["allocatable"]["pods"])
        assert _ALLOCATABLE_PODS_MIN <= allocatable_pods <= _ALLOCATABLE_PODS_MAX, (
            f"the Node advertises allocatable pods = {allocatable_pods}, outside "
            f"[{_ALLOCATABLE_PODS_MIN}, {_ALLOCATABLE_PODS_MAX}]; on {_NODE_TYPE} the VPC CNI's "
            f"ENI x secondary-IP limit is what bounds this, so an unbounded figure means no IPAM"
        )

        # (4) The CNI attached at least one ENI of its OWN, named after this instance. Note the
        #     instance's original primary ENI has an empty Description and the CNI hands out
        #     secondary addresses on that one too, so this is asserted over the interface set, not
        #     per pod.
        enis_before = _instance_enis(ec2, instance_id)
        descriptions = [e.get("Description") or "" for e in enis_before]
        assert f"{_CNI_ENI_DESC_PREFIX}{instance_id}" in descriptions, (
            f"no ENI attached to {instance_id!r} is described "
            f"{_CNI_ENI_DESC_PREFIX + instance_id!r}; the VPC CNI names every interface it attaches "
            f"after the instance, so its absence means pod addressing is not coming from the CNI. "
            f"descriptions were {descriptions!r}"
        )

        _k8s_json(ctx, conn, "POST", "/api/v1/namespaces",
                  body={"apiVersion": "v1", "kind": "Namespace",
                        "metadata": {"name": ns,
                                     "labels": {"sim2real": "b3-eks-workloads"}}})
        ctx.on_cleanup(lambda: _unless_cluster_gone(
            ctx, cluster_name,
            lambda: _k8s(ctx, conn, "DELETE", f"/api/v1/namespaces/{ns}", timeout_s=90)))

        pod_ips = {}
        for pod in (pod_a, pod_b):
            _k8s_json(ctx, conn, "POST", f"/api/v1/namespaces/{ns}/pods",
                      body=_sleeper(pod, node_name))
            running = _wait_for(
                lambda: _k8s_json(ctx, conn, "GET", f"/api/v1/namespaces/{ns}/pods/{pod}"),
                lambda p: p["status"]["phase"] == "Running" and p["status"].get("podIP"),
                timeout_s=_POD_TIMEOUT_S,
                interval_s=5,
                desc=f"pod {pod} Running with a podIP",
            )
            assert running["spec"]["nodeName"] == node_name, (
                f"pod {pod!r} landed on {running['spec']['nodeName']!r}, not the node it was "
                f"pinned to ({node_name!r})"
            )
            pod_ips[pod] = running["status"]["podIP"]

        enis_after = _instance_enis(ec2, instance_id)
        addrs = _eni_addresses(enis_after)
        eni_subnet_ids = sorted({e["SubnetId"] for e in enis_after})
        subnet_cidrs = {
            s["SubnetId"]: ipaddress.ip_network(s["CidrBlock"])
            for s in ec2.describe_subnets(SubnetIds=eni_subnet_ids)["Subnets"]
        }
        eni_subnet_of = {e["NetworkInterfaceId"]: e["SubnetId"] for e in enis_after}

        for pod, ip in pod_ips.items():
            # (5) THE HEADLINE: AWS itself believes this address exists, on an ENI of this node's
            #     instance. An emulator that invents pod IPs fails here with nothing to replay.
            assert ip in addrs, (
                f"pod {pod!r} reports podIP {ip!r}, but no ENI attached to instance "
                f"{instance_id!r} carries that address. DescribeNetworkInterfaces reported "
                f"{sorted(addrs)!r} -- the pod address is not a VPC address at all"
            )
            eni_id, is_primary = addrs[ip]

            # (6) It is a SECONDARY address. An emulator that reports the node's own primary IP as
            #     the pod IP fails here.
            assert is_primary is False, (
                f"pod {pod!r}'s podIP {ip!r} is the PRIMARY address of {eni_id!r}; the VPC CNI "
                f"hands pods secondary addresses, and reusing an interface's primary would collide "
                f"with the node itself"
            )

            # (7) It is inside the CIDR of the SUBNET that ENI sits in -- not merely somewhere in
            #     the VPC, which is what routing, NACLs and SG-per-pod actually depend on.
            cidr = subnet_cidrs[eni_subnet_of[eni_id]]
            assert ipaddress.ip_address(ip) in cidr, (
                f"pod {pod!r}'s podIP {ip!r} is not inside {cidr!r}, the CIDR of subnet "
                f"{eni_subnet_of[eni_id]!r} that carries ENI {eni_id!r}"
            )

            # (8) Pod and node are distinct addresses.
            assert ip != node_internal_ip, (
                f"pod {pod!r}'s podIP equals the node's InternalIP {node_internal_ip!r}, so no "
                f"per-pod address was allocated at all"
            )

        # (9) Two pods on the SAME instance got two DISTINCT secondary addresses -- the allocation
        #     is per pod, not one shared address echoed twice.
        assert pod_ips[pod_a] != pod_ips[pod_b], (
            f"both pods on instance {instance_id!r} report the same podIP {pod_ips[pod_a]!r}"
        )

        # (10) EFFECT SCOPED: no other instance in the account carries either pod's address.
        others = [
            i["InstanceId"]
            for page in ec2.get_paginator("describe_instances").paginate(
                Filters=[{"Name": "instance-state-name", "Values": ["running"]}])
            for r in page["Reservations"] for i in r["Instances"]
            if i["InstanceId"] != instance_id
        ]
        for other in others:
            foreign = _eni_addresses(_instance_enis(ec2, other))
            clash = sorted(set(pod_ips.values()) & set(foreign))
            assert clash == [], (
                f"instance {other!r} also carries {clash!r}, so the pod addresses are not "
                f"uniquely allocated within the VPC"
            )

        # (11) A WARM POOL exists: the instance's ENIs carry strictly more secondary addresses than
        #      there are pods holding an address on this node. This surplus is what makes the
        #      release behaviour in (12) the expected one.
        secondary = {ip for ip, (_, prim) in addrs.items() if prim is False}
        on_node = {
            p["status"]["podIP"]
            for p in _k8s_json(ctx, conn, "GET",
                               f"/api/v1/pods?fieldSelector=spec.nodeName%3D{node_name}")["items"]
            if p["status"].get("podIP")
        }
        assert len(secondary) > len(on_node), (
            f"the ENIs of {instance_id!r} hold {len(secondary)} secondary addresses while "
            f"{len(on_node)} pods on that node hold one; the VPC CNI keeps a warm pool, so there "
            f"must be a surplus. secondary={sorted(secondary)!r} pod_ips={sorted(on_node)!r}"
        )
        assert on_node >= set(pod_ips.values()), (
            f"the node's own pod list does not report {sorted(set(pod_ips.values()) - on_node)!r}"
        )

        # (12) RELEASE ARM: delete pod B. Its address REMAINS on the ENI (warm pool)
        #      and is no longer claimed by any pod in the cluster. Pod A's is still claimed.
        _k8s(ctx, conn, "DELETE",
             f"/api/v1/namespaces/{ns}/pods/{pod_b}?gracePeriodSeconds=0", timeout_s=90)
        _wait_for(
            lambda: _k8s(ctx, conn, "GET", f"/api/v1/namespaces/{ns}/pods/{pod_b}")[0],
            lambda code: code == 404,
            timeout_s=_POD_TIMEOUT_S,
            interval_s=5,
            desc=f"pod {pod_b} gone from the API",
        )
        held_at_delete = set(_eni_addresses(_instance_enis(ec2, instance_id)))
        deadline = time.monotonic() + _RELEASE_OBSERVE_S
        while True:
            claimed = _claimed_pod_ips(ctx, conn)
            held = _eni_addresses(_instance_enis(ec2, instance_id))
            assert set(held) >= held_at_delete, (
                f"deleting one pod removed {sorted(held_at_delete - set(held))!r} from the "
                f"instance's ENIs; the measured VPC CNI behaviour recycles inside the ENI's warm "
                f"pool and returns nothing to the subnet"
            )
            assert pod_ips[pod_b] in held, (
                f"the deleted pod's address {pod_ips[pod_b]!r} left the ENI within "
                f"{_RELEASE_OBSERVE_S}s. The VPC CNI keeps it in its warm "
                f"pool; ENI addresses are now {sorted(held)!r}"
            )
            assert pod_ips[pod_b] not in claimed, (
                f"the deleted pod's address {pod_ips[pod_b]!r} is still claimed by a pod in the "
                f"cluster: claimed set {sorted(claimed)!r}"
            )
            assert pod_ips[pod_a] in claimed and pod_ips[pod_a] in held, (
                f"the surviving pod {pod_a!r} lost its address {pod_ips[pod_a]!r}: claimed="
                f"{pod_ips[pod_a] in claimed} on_eni={pod_ips[pod_a] in held}"
            )
            if time.monotonic() >= deadline:
                break
            time.sleep(2)

        _k8s(ctx, conn, "DELETE", f"/api/v1/namespaces/{ns}", timeout_s=90)
        _wait_for(
            lambda: _k8s(ctx, conn, "GET", f"/api/v1/namespaces/{ns}")[0],
            lambda code: code == 404,
            timeout_s=_NS_DELETE_TIMEOUT_S,
            interval_s=5,
            desc=f"namespace {ns} deleted",
        )
    except BaseException:
        # Set so the inline teardown's own failure cannot mask the fidelity finding that caused it.
        body_failed.append(True)
        raise
    finally:
        try:
            _teardown_cluster(eks, cluster_name)
            _delete_role(iam, node_role)
            _delete_role(iam, cluster_role)
        except BaseException:
            if not body_failed:
                raise

    surviving = [n for n in eks.list_clusters().get("clusters", []) if n == cluster_name]
    assert surviving == [], (
        f"the control plane {cluster_name!r} survived the inline teardown: ListClusters still "
        f"reports {surviving!r}, which is a billable leak"
    )
    live = [
        i["InstanceId"]
        for page in ec2.get_paginator("describe_instances").paginate(
            Filters=[{"Name": "tag:eks:cluster-name", "Values": [cluster_name]},
                     {"Name": "instance-state-name",
                      "Values": ["pending", "running", "stopping", "stopped"]}])
        for r in page["Reservations"] for i in r["Instances"]
    ]
    assert live == [], (
        f"node group instances {live!r} outlived the inline teardown of {cluster_name!r}"
    )


def _unless_cluster_gone(ctx, name, fn):
    """Run a cluster-scoped teardown unless the cluster is already deleted, which took it along."""
    if _cluster_status(ctx.client("eks"), name) != "GONE":
        fn()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
