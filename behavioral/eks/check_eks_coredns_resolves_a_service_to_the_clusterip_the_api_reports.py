"""eks-coredns-resolves-a-service-to-the-clusterip-the-api-reports."""
from __future__ import annotations

import base64
import ipaddress
import json
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


CHECK = "eks-coredns-resolves-a-service-to-the-clusterip-the-api-reports"
GROUP = 'data-plane'
SERVICES = ['eks']

# The shared cluster fixture.
_SHARED_CLUSTER = "sim2real-ga-eks-shr"
_SHARED_NODEGROUP = "shared-ng"
_CLUSTER_ROLE = "sim2real-ga-eks-cluster-role"
_NODE_ROLE = "sim2real-ga-eks-node-role"
_EKS_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
_NODE_POLICIES = (
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
)
_BAD_AZS = {"us-west-2d", "us-east-1e", "us-east-1f", "ca-central-1d"}
_NODE_TYPE = "t3.medium"
_FIXTURE_TAGS = {"sim2real:managed": "true", "sim2real": "ga-depth-eks"}

_CLUSTER_TIMEOUT_S = 1500
_DELETE_RETRY_TIMEOUT_S = 900
_NODEGROUP_TIMEOUT_S = 900
_POD_TIMEOUT_S = 420
_ROLE_PROPAGATION_TIMEOUT_S = 120

_IMAGE = "public.ecr.aws/docker/library/busybox:1.36"


# ===== helpers =====


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


def _ensure_role(ctx, name, service, managed_policies=()):
    """Create-or-reuse the fixture's IAM role and return its ARN."""
    iam = ctx.client("iam")
    try:
        arn = iam.create_role(
            RoleName=name,
            AssumeRolePolicyDocument=_trust(service),
            Description="sim2real ga-depth eks shared fixture",
        )["Role"]["Arn"]
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "EntityAlreadyExists":
            arn = iam.get_role(RoleName=name)["Role"]["Arn"]
        elif code in ("AccessDenied", "AccessDeniedException"):
            raise AssertionError(f"identity cannot create IAM role {name}: {exc}") from exc
        else:
            raise
    for policy_arn in managed_policies:
        try:
            iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
        except ClientError:
            pass
    return arn


def _retry_on_role_not_ready(fn, desc):
    """Retry fn() while IAM's eventual consistency makes EKS's synchronous role-validation
    transiently reject a role this run just created.

    A bare `time.sleep` before the first attempt is a guess at how long propagation takes; this
    retries the actual call that depends on it, bounded by a deadline, so a target that
    propagates faster does not pay a fixed tax and one that is genuinely slower still succeeds.
    """
    deadline = time.monotonic() + _ROLE_PROPAGATION_TIMEOUT_S
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            if code != "InvalidParameterException" or "role" not in message.lower():
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"{desc} was still refused with InvalidParameterException on the role "
                    f"after {_ROLE_PROPAGATION_TIMEOUT_S}s: {exc}"
                ) from exc
            time.sleep(2)


def _fixture_subnets(ctx):
    """Default-VPC subnets in EKS-supported AZs that actually offer the node instance type."""
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
        if z["ZoneName"] in offered and z["ZoneName"] not in _BAD_AZS
    }
    assert usable, (
        f"no available AZ in {ctx.region} offers {_NODE_TYPE!r}; offerings were "
        f"{sorted(offered)!r}"
    )
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    ).get("Subnets", [])
    by_az = {}
    for sn in sorted(subnets, key=lambda s: s["AvailabilityZone"]):
        if sn["AvailabilityZone"] in usable:
            by_az.setdefault(sn["AvailabilityZone"], sn["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError(
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


def _delete_with_retry(fn, desc):
    """Issue a delete AWS can transiently refuse, retrying it within a bounded budget.

    DeleteCluster can answer ResourceInUseException ("currently has an update in progress") on an
    ACTIVE cluster with no dependents while ListUpdates is empty, so the delete itself is retried.
    """
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
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"{desc} was still refused with ResourceInUseException after "
                    f"{_DELETE_RETRY_TIMEOUT_S}s: {exc}"
                ) from exc
            time.sleep(2)


def _teardown_nodegroup(c, cluster, ng):
    _delete_with_retry(
        lambda: c.delete_nodegroup(clusterName=cluster, nodegroupName=ng),
        f"delete nodegroup {ng}",
    )
    _wait_for(
        lambda: _nodegroup_status(c, cluster, ng),
        lambda s: s == "GONE",
        timeout_s=_NODEGROUP_TIMEOUT_S,
        interval_s=20,
        desc=f"nodegroup {ng} deleted",
    )


def _teardown_cluster(c, name):
    """Drain dependents then delete the control plane, polling it to actually gone."""
    try:
        for ng in c.list_nodegroups(clusterName=name).get("nodegroups", []):
            _teardown_nodegroup(c, name, ng)
        for addon in c.list_addons(clusterName=name).get("addons", []):
            try:
                c.delete_addon(clusterName=name, addonName=addon, preserve=False)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        for fp in c.list_fargate_profiles(clusterName=name).get("fargateProfileNames", []):
            c.delete_fargate_profile(clusterName=name, fargateProfileName=fp)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    _delete_with_retry(lambda: c.delete_cluster(name=name), f"delete cluster {name}")
    _wait_for(
        lambda: _cluster_status(c, name),
        lambda s: s == "GONE",
        timeout_s=_CLUSTER_TIMEOUT_S,
        interval_s=20,
        desc=f"cluster {name} fully deleted",
    )


def _adopt_or_create_cluster(ctx):
    """Return (endpoint, ca_pem, cluster) for the shared ACTIVE cluster."""
    c = ctx.client("eks")
    role_arn = _ensure_role(ctx, _CLUSTER_ROLE, "eks.amazonaws.com", [_EKS_CLUSTER_POLICY])
    subnet_ids = _fixture_subnets(ctx)
    try:
        _retry_on_role_not_ready(
            lambda: c.create_cluster(
                name=_SHARED_CLUSTER,
                roleArn=role_arn,
                resourcesVpcConfig={
                    "subnetIds": subnet_ids,
                    "endpointPublicAccess": True,
                    "endpointPrivateAccess": False,
                },
                accessConfig={
                    "authenticationMode": "API_AND_CONFIG_MAP",
                    "bootstrapClusterCreatorAdminPermissions": True,
                },
                tags=dict(_FIXTURE_TAGS),
            ),
            f"create cluster {_SHARED_CLUSTER}",
        )
        ctx.on_cleanup(lambda: _teardown_cluster(c, _SHARED_CLUSTER))
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceInUseException":
            raise
    cluster = _wait_for(
        lambda: c.describe_cluster(name=_SHARED_CLUSTER)["cluster"],
        lambda cl: cl["status"] in ("ACTIVE", "FAILED"),
        timeout_s=_CLUSTER_TIMEOUT_S,
        interval_s=20,
        desc=f"cluster {_SHARED_CLUSTER} ACTIVE",
    )
    assert cluster["status"] == "ACTIVE", (
        f"shared cluster landed in {cluster['status']!r}; health={cluster.get('health')!r}"
    )
    ca_pem = base64.b64decode(cluster["certificateAuthority"]["data"]).decode("ascii")
    assert ca_pem.startswith("-----BEGIN CERTIFICATE-----"), (
        f"certificateAuthority.data did not decode to a PEM certificate: {ca_pem[:60]!r}"
    )
    return (cluster["endpoint"], ca_pem), cluster


def _adopt_or_create_nodegroup(ctx):
    """Ensure the shared managed node group is ACTIVE -- CoreDNS needs somewhere to run."""
    c = ctx.client("eks")
    node_role_arn = _ensure_role(ctx, _NODE_ROLE, "ec2.amazonaws.com", _NODE_POLICIES)
    subnet_ids = _fixture_subnets(ctx)
    try:
        _retry_on_role_not_ready(
            lambda: c.create_nodegroup(
                clusterName=_SHARED_CLUSTER,
                nodegroupName=_SHARED_NODEGROUP,
                subnets=subnet_ids,
                nodeRole=node_role_arn,
                scalingConfig={"minSize": 2, "maxSize": 2, "desiredSize": 2},
                instanceTypes=[_NODE_TYPE],
                amiType="AL2023_x86_64_STANDARD",
                capacityType="ON_DEMAND",
                diskSize=20,
                tags=dict(_FIXTURE_TAGS),
            ),
            f"create nodegroup {_SHARED_NODEGROUP}",
        )
        ctx.on_cleanup(lambda: _teardown_nodegroup(c, _SHARED_CLUSTER, _SHARED_NODEGROUP))
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceInUseException":
            raise
    status = _wait_for(
        lambda: _nodegroup_status(c, _SHARED_CLUSTER, _SHARED_NODEGROUP),
        lambda s: s in ("ACTIVE", "CREATE_FAILED", "DEGRADED"),
        timeout_s=_NODEGROUP_TIMEOUT_S,
        interval_s=20,
        desc=f"nodegroup {_SHARED_NODEGROUP} ACTIVE",
    )
    assert status == "ACTIVE", f"shared node group landed in {status!r}"


def _k8s_token(ctx, cluster_name, *, ttl_s=900):
    """Mint the EKS Kubernetes bearer token for the CURRENT caller (k8s-aws-v1 scheme)."""
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
    base, ca_pem = conn
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_ctx.check_hostname = True
    ssl_ctx.verify_mode = ssl.CERT_REQUIRED
    ssl_ctx.load_verify_locations(cadata=ca_pem)
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {_k8s_token(ctx, _SHARED_CLUSTER)}",
    }
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


def _delete_namespace(ctx, conn, ns):
    _k8s(ctx, conn, "DELETE", f"/api/v1/namespaces/{ns}", timeout_s=90)


def _sections(text):
    """Split a pod's log into the labelled sections the pod script printed.

    Parsed structurally off the markers rather than by line offset, so an extra line of
    resolver noise cannot shift the fields the assertions read.
    """
    out = {}
    for chunk in text.split("<<<")[1:]:
        label, _, rest = chunk.partition("\n")
        payload, _, tail = rest.partition(">>>RC=")
        out[label.strip()] = (payload, tail.split("\n", 1)[0].strip())
    return out


def _answers(section):
    """The answer addresses in a busybox `nslookup` section.

    The resolver's own endpoint is printed as `Address: <ip>:53`, so entries carrying a port are
    the server and everything else is an answer -- a structural filter rather than a line index.
    """
    ips = []
    for line in section.splitlines():
        line = line.strip()
        if not line.startswith("Address"):
            continue
        value = line.split(":", 1)[1].strip().split()[0] if ":" in line else ""
        if not value or ":" in value:
            continue
        ips.append(value)
    return ips


@tags("axis:happy-path", "concern:data-plane", "dp:native", "plane:data", "cap:c1", "cap:c5")
def run(ctx) -> None:
    """An in-cluster lookup of <svc>.<ns>.svc.cluster.local and the bare Service name return
    exactly the ClusterIP the Kubernetes API reports, an unknown name does not resolve, and the
    pod's resolver is the kube-dns Service ClusterIP with CoreDNS running behind it."""
    conn, cluster = _adopt_or_create_cluster(ctx)
    _adopt_or_create_nodegroup(ctx)

    service_cidr = cluster["kubernetesNetworkConfig"]["serviceIpv4Cidr"]

    ns = ctx.unique_name("sim2real-dns-")[:63].lower()
    app = "sim2real-dns-web"
    _k8s_json(
        ctx, conn, "POST", "/api/v1/namespaces",
        body={"apiVersion": "v1", "kind": "Namespace",
              "metadata": {"name": ns, "labels": {"sim2real": "ga-depth-eks"}}},
    )
    ctx.on_cleanup(lambda: _delete_namespace(ctx, conn, ns))

    _k8s_json(
        ctx, conn, "POST", f"/apis/apps/v1/namespaces/{ns}/deployments",
        body={
            "apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": app},
            "spec": {
                "replicas": 1,
                "selector": {"matchLabels": {"app": app}},
                "template": {
                    "metadata": {"labels": {"app": app}},
                    "spec": {"containers": [{
                        "name": "web", "image": _IMAGE,
                        "command": ["sh", "-c",
                                    "mkdir -p /www && echo ok > /www/index.html"
                                    " && exec httpd -f -p 8080 -h /www"],
                        "ports": [{"containerPort": 8080}],
                    }]},
                },
            },
        },
    )
    svc_obj = _k8s_json(
        ctx, conn, "POST", f"/api/v1/namespaces/{ns}/services",
        body={
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": app},
            "spec": {"type": "ClusterIP", "selector": {"app": app},
                     "ports": [{"port": 8080, "targetPort": 8080}]},
        },
    )
    cluster_ip = svc_obj["spec"]["clusterIP"]

    # (1) The ClusterIP the API allocated really lies inside the service CIDR the EKS control
    #     plane advertises for this cluster.
    assert ipaddress.ip_address(cluster_ip) in ipaddress.ip_network(service_cidr), (
        f"the Service got ClusterIP {cluster_ip!r}, which is outside the serviceIpv4Cidr "
        f"{service_cidr!r} DescribeCluster advertises"
    )

    _wait_for(
        lambda: _k8s_json(ctx, conn, "GET", f"/apis/apps/v1/namespaces/{ns}/deployments/{app}"),
        lambda d: d.get("status", {}).get("readyReplicas") == 1,
        timeout_s=_POD_TIMEOUT_S,
        interval_s=6,
        desc=f"deployment {app} ready",
    )

    fqdn = f"{app}.{ns}.svc.cluster.local"
    nxd = f"no-such-service.{ns}.svc.cluster.local"
    script = (
        "for i in $(seq 1 30); do nslookup " + fqdn + " >/dev/null 2>&1 && break; sleep 2; done\n"
        "echo '<<<FQDN'; nslookup " + fqdn + " 2>&1; echo \">>>RC=$?\"\n"
        "echo '<<<SHORT'; nslookup " + app + " 2>&1; echo \">>>RC=$?\"\n"
        "echo '<<<NXD'; nslookup " + nxd + " 2>&1; echo \">>>RC=$?\"\n"
        "echo '<<<RESOLV'; cat /etc/resolv.conf; echo \">>>RC=$?\"\n"
    )
    pod = "sim2real-resolver"
    _k8s_json(
        ctx, conn, "POST", f"/api/v1/namespaces/{ns}/pods",
        body={
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": pod},
            "spec": {"restartPolicy": "Never",
                     "containers": [{"name": "resolver", "image": _IMAGE,
                                     "command": ["sh", "-c", script]}]},
        },
    )
    finished = _wait_for(
        lambda: _k8s_json(ctx, conn, "GET", f"/api/v1/namespaces/{ns}/pods/{pod}"),
        lambda p: p["status"]["phase"] in ("Succeeded", "Failed"),
        timeout_s=_POD_TIMEOUT_S,
        interval_s=5,
        desc=f"resolver pod {pod} terminal",
    )
    assert finished["status"]["phase"] == "Succeeded", (
        f"the resolver pod ended {finished['status']['phase']!r}: {finished['status']!r}"
    )
    status, log = _k8s(ctx, conn, "GET", f"/api/v1/namespaces/{ns}/pods/{pod}/log")
    assert status == 200, f"could not read the resolver pod's logs: {status} {log[:300]!r}"
    text = log.decode("utf-8", "replace")
    sec = _sections(text)
    assert set(sec) == {"FQDN", "SHORT", "NXD", "RESOLV"}, (
        f"the resolver pod produced sections {sorted(sec)!r}; full log {text!r}"
    )

    # (2) CoreDNS answers the fully qualified Service name with exactly the API's ClusterIP.
    assert _answers(sec["FQDN"][0]) == [cluster_ip], (
        f"in-cluster DNS answered {fqdn!r} with {_answers(sec['FQDN'][0])!r}, but the Kubernetes "
        f"API reports ClusterIP {cluster_ip!r}; raw answer {sec['FQDN'][0]!r}"
    )

    # (3) The pod's search path resolves the bare Service name to the same address.
    assert _answers(sec["SHORT"][0]) == [cluster_ip], (
        f"the bare Service name {app!r} resolved to {_answers(sec['SHORT'][0])!r} instead of "
        f"{cluster_ip!r}; the kubelet must write a search path that makes this work. raw "
        f"{sec['SHORT'][0]!r}"
    )

    # (4) An unknown name in the same zone does not resolve, and the SAME pod's two lookups above
    #     succeeding is what proves this is a real negative answer rather than a broken resolver.
    assert sec["NXD"][1] != "0", (
        f"the unknown name {nxd!r} resolved successfully (rc={sec['NXD'][1]!r}): "
        f"{sec['NXD'][0]!r}"
    )
    assert _answers(sec["NXD"][0]) == [], (
        f"cluster DNS returned answer addresses {_answers(sec['NXD'][0])!r} for a name that does "
        f"not exist: {sec['NXD'][0]!r}"
    )

    # (5) The resolver the pod was handed is the kube-dns Service, i.e. cluster DNS proper.
    kube_dns = _k8s_json(ctx, conn, "GET", "/api/v1/namespaces/kube-system/services/kube-dns")
    nameservers = [
        line.split()[1]
        for line in sec["RESOLV"][0].splitlines()
        if line.strip().startswith("nameserver")
    ]
    assert nameservers == [kube_dns["spec"]["clusterIP"]], (
        f"the pod's /etc/resolv.conf points at {nameservers!r}, but the cluster's kube-dns "
        f"Service has ClusterIP {kube_dns['spec']['clusterIP']!r}: {sec['RESOLV'][0]!r}"
    )

    # (6) ... and CoreDNS is really running behind that Service.
    coredns = _k8s_json(
        ctx, conn, "GET", "/apis/apps/v1/namespaces/kube-system/deployments/coredns"
    )
    assert coredns["status"].get("readyReplicas", 0) >= 1, (
        f"cluster DNS answered, but the coredns Deployment reports "
        f"{coredns['status'].get('readyReplicas')!r} ready replicas: {coredns['status']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
