"""eks-irsa-projected-token-assumed-inside-the-pod-and-sub-condition-denied."""
from __future__ import annotations

import base64
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


CHECK = "eks-irsa-projected-token-assumed-inside-the-pod-and-sub-condition-denied"
GROUP = 'data-plane-rejected'
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

# ~2x margins on typical cluster (~450 s), node group (~120 s) and pod (~16 s) durations; their
# sum must stay under the check's overall time budget so teardown is never cut off.
_CLUSTER_TIMEOUT_S = 800
_CLUSTER_DELETE_TIMEOUT_S = 500
_NODEGROUP_TIMEOUT_S = 500
_NODEGROUP_DELETE_TIMEOUT_S = 1200.0
_DELETE_RETRY_TIMEOUT_S = 240
_POD_TIMEOUT_S = 420
_NS_DELETE_TIMEOUT_S = 240

# Pinned so the image cannot drift; it carries a working AWS SDK, so the credential is consumed
# by a process this check did not write.
_IMAGE = "public.ecr.aws/aws-cli/aws-cli:2.36.44"
_SA_OK = "sim2real-irsa-ok"
_SA_BAD = "sim2real-irsa-bad"
# A ServiceAccount name that is never created, so role B's trust condition names a subject that
# cannot exist. The BAD pod runs under _SA_BAD and therefore presents a valid, correctly signed
# token whose `sub` simply does not match its own role's condition.
_SA_NEVER = "sim2real-irsa-never-exists"
_PAYLOAD_OK = "sim2real-b3-irsa-ok-4f71a2"
_PAYLOAD_BAD = "sim2real-b3-irsa-bad-8c3e05"
_KEY_OK = "ok.txt"
_KEY_BAD = "bad.txt"
_TOKEN_ENV = "AWS_WEB_IDENTITY_TOKEN_FILE"
_ROLE_ENV = "AWS_ROLE_ARN"
_TOKEN_VOLUME = "aws-iam-token"
_TOKEN_MOUNT = "/var/run/secrets/eks.amazonaws.com/serviceaccount"
_IRSA_AUDIENCE = "sts.amazonaws.com"
_STS_AUDIENCE_CLAIM = "sts.amazonaws.com"


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


def _create_role(ctx, name, assume_policy, managed_policies=()):
    iam = ctx.client("iam")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=assume_policy,
        Description="sim2real b3-eks-workloads irsa check",
        Tags=[{"Key": k, "Value": v} for k, v in _FIXTURE_TAGS.items()],
    )["Role"]["Arn"]
    for policy_arn in managed_policies:
        iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
    # IAM is eventually consistent with nothing to poll; every caller already waits past that
    # window (cluster-create retry, nodegroup after ACTIVE, the OK pod's bounded retry).
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
    """Drain the node group, delete the control plane, and poll until both are actually gone.

    Called inline from the check body's `finally`: on_cleanup alone has too short a budget for EKS.
    """
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

    A fresh sts client each call: botocore's add_header appends, so a cached client double-signs.
    """
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


def _sections(text):
    """Split the pod's log into the labelled sections its script printed.

    Parsed structurally off the markers rather than by line offset, so a retry line or a stray
    warning cannot shift the fields the assertions read.
    """
    out = {}
    for chunk in text.split("<<<")[1:]:
        label, _, rest = chunk.partition("\n")
        payload, _, tail = rest.partition(">>>RC=")
        out[label.strip()] = (payload, tail.split("\n", 1)[0].strip())
    return out


def _drop_bucket(s3, name):
    try:
        pages = list(s3.get_paginator("list_object_versions").paginate(Bucket=name))
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchBucket":
            return
        raise
    for page in pages:
        stale = [
            {"Key": o["Key"], "VersionId": o["VersionId"]}
            for o in list(page.get("Versions", [])) + list(page.get("DeleteMarkers", []))
        ]
        if stale:
            s3.delete_objects(Bucket=name, Delete={"Objects": stale})
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _error_code(fn):
    """The AWS error code a call is refused with; raise if the call unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError("the call was expected to be refused but it SUCCEEDED")


def _all_keys(s3, bucket):
    """Every key in the bucket, paginated, so a membership assertion is a real bound."""
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return sorted(keys)


def _irsa_trust(provider_arn, issuer_host, subject):
    """A role trust policy that federates the cluster's OIDC provider for exactly one subject."""
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": provider_arn},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {"StringEquals": {
                f"{issuer_host}:sub": subject,
                f"{issuer_host}:aud": _IRSA_AUDIENCE,
            }},
        }],
    })


def _pod_manifest(sa, pod, image, script, env):
    return {
        "apiVersion": "v1", "kind": "Pod", "metadata": {"name": pod},
        "spec": {
            "restartPolicy": "Never",
            "serviceAccountName": sa,
            "containers": [{
                "name": "cli", "image": image,
                "command": ["/bin/sh", "-c", script],
                "env": [{"name": k, "value": v} for k, v in env.items()],
            }],
        },
    }


def _run_pod(ctx, conn, ns, pod, manifest):
    """Create the pod, wait for it to terminate, and return (admitted spec, phase, sections)."""
    admitted = _k8s_json(ctx, conn, "POST", f"/api/v1/namespaces/{ns}/pods", body=manifest)
    finished = _wait_for(
        lambda: _k8s_json(ctx, conn, "GET", f"/api/v1/namespaces/{ns}/pods/{pod}"),
        lambda p: p["status"]["phase"] in ("Succeeded", "Failed"),
        timeout_s=_POD_TIMEOUT_S,
        interval_s=6,
        desc=f"pod {pod} terminal",
    )
    status, log = _k8s(ctx, conn, "GET", f"/api/v1/namespaces/{ns}/pods/{pod}/log")
    assert status == 200, f"could not read pod {pod}'s logs: {status} {log[:300]!r}"
    text = log.decode("utf-8", "replace")
    return admitted, finished, text, _sections(text)


# The OK pod retries its FIRST AWS call: the OIDC provider and the role trust policy are both
# eventually consistent and neither exposes a condition to poll, so the bounded retry at first use
# of the permission is the only correct shape. Exhausting it FAILS.
_SCRIPT_OK = (
    'echo "<<<TOKENFILE"; wc -c < "$AWS_WEB_IDENTITY_TOKEN_FILE" 2>&1; echo ">>>RC=$?"\n'
    'for i in $(seq 1 40); do aws sts get-caller-identity >/dev/null 2>&1 && break; sleep 4; done\n'
    'echo "<<<WHOAMI"; aws sts get-caller-identity 2>&1; echo ">>>RC=$?"\n'
    'echo "<<<PUT"; echo -n "$PAYLOAD" | aws s3 cp - "s3://$BUCKET/$KEY" 2>&1; echo ">>>RC=$?"\n'
    'exit 0\n'
)
# The BAD pod does NOT retry, and does not need to: it runs only after the OK pod has already
# proved the provider and the trust policies are effective, so a refusal here cannot be
# propagation lag. `exit 0` so the container's own exit status stays a control -- the refusal must
# be an authorization decision, not a crashed container.
_SCRIPT_BAD = (
    'echo "<<<TOKENFILE"; wc -c < "$AWS_WEB_IDENTITY_TOKEN_FILE" 2>&1; echo ">>>RC=$?"\n'
    'echo "<<<WHOAMI"; aws sts get-caller-identity 2>&1; echo ">>>RC=$?"\n'
    'echo "<<<PUT"; echo -n "$PAYLOAD" | aws s3 cp - "s3://$BUCKET/$KEY" 2>&1; echo ">>>RC=$?"\n'
    'exit 0\n'
)


@tags("axis:rejection", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An IRSA pod's in-container SDK exchanges its projected token via AssumeRoleWithWebIdentity
    and writes to S3; a pod whose ServiceAccount fails its role's `sub` condition gets AccessDenied
    and its object never appears.

    Reference: https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html
    """
    eks = ctx.client("eks")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    account = ctx.client("sts").get_caller_identity()["Account"]
    suffix = ctx.unique_name("")[:8]
    cluster_name = f"sim2real-b3-irsa-{suffix}"
    nodegroup = "irsa-ng"
    cluster_role = f"sim2real-b3-irsa-cr-{suffix}"
    node_role = f"sim2real-b3-irsa-nr-{suffix}"
    role_ok = f"sim2real-b3-irsa-ok-{suffix}"
    role_bad = f"sim2real-b3-irsa-bad-{suffix}"
    ns = f"sim2real-b3-irsa-{suffix}"
    bucket = f"sim2real-b3-irsa-{suffix}".lower()
    provider_arn = None
    # Set when the body fails, so a teardown failure cannot mask the original assertion error.
    body_failed = []

    s3.create_bucket(Bucket=bucket,
                     CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _drop_bucket(s3, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in _FIXTURE_TAGS.items()]},
    )

    cluster_role_arn = _create_role(
        ctx, cluster_role, _trust("eks.amazonaws.com"), [_CLUSTER_ROLE_POLICY]
    )
    ctx.on_cleanup(lambda: _delete_role(iam, cluster_role))
    node_role_arn = _create_role(ctx, node_role, _trust("ec2.amazonaws.com"), _NODE_POLICIES)
    ctx.on_cleanup(lambda: _delete_role(iam, node_role))

    cluster = _create_cluster(ctx, cluster_name, cluster_role_arn)
    ctx.on_cleanup(lambda: _teardown_cluster(eks, cluster_name))
    ca_pem = base64.b64decode(cluster["certificateAuthority"]["data"]).decode("ascii")
    assert ca_pem.startswith("-----BEGIN CERTIFICATE-----"), (
        f"certificateAuthority.data did not decode to a PEM certificate: {ca_pem[:60]!r}"
    )
    conn = (cluster["endpoint"], ca_pem, cluster_name)
    issuer = cluster["identity"]["oidc"]["issuer"]
    issuer_host = issuer.split("://", 1)[1]

    try:
        _create_nodegroup(ctx, cluster_name, nodegroup, node_role_arn)

        # The OIDC provider is keyed on the issuer URL, unique per cluster, so it is never shared.
        provider_arn = iam.create_open_id_connect_provider(
            Url=issuer,
            ClientIDList=[_IRSA_AUDIENCE],
            Tags=[{"Key": k, "Value": v} for k, v in _FIXTURE_TAGS.items()],
        )["OpenIDConnectProviderArn"]
        ctx.on_cleanup(
            lambda: _gone_ok(lambda: iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn))
        )

        # Two roles, IDENTICAL except for the subject their trust condition names.
        s3_policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["s3:PutObject", "s3:GetObject"],
                           "Resource": f"arn:aws:s3:::{bucket}/*"}],
        })
        arn_ok = _create_role(
            ctx, role_ok,
            _irsa_trust(provider_arn, issuer_host, f"system:serviceaccount:{ns}:{_SA_OK}"),
        )
        ctx.on_cleanup(lambda: _delete_role(iam, role_ok))
        iam.put_role_policy(RoleName=role_ok, PolicyName="s3-one-bucket",
                            PolicyDocument=s3_policy)
        arn_bad = _create_role(
            ctx, role_bad,
            # The ONE varied thing: a subject naming a ServiceAccount that is never created.
            _irsa_trust(provider_arn, issuer_host, f"system:serviceaccount:{ns}:{_SA_NEVER}"),
        )
        ctx.on_cleanup(lambda: _delete_role(iam, role_bad))
        iam.put_role_policy(RoleName=role_bad, PolicyName="s3-one-bucket",
                            PolicyDocument=s3_policy)

        _k8s_json(ctx, conn, "POST", "/api/v1/namespaces",
                  body={"apiVersion": "v1", "kind": "Namespace",
                        "metadata": {"name": ns,
                                     "labels": {"sim2real": "b3-eks-workloads"}}})
        ctx.on_cleanup(lambda: _unless_cluster_gone(ctx, cluster_name, lambda: _k8s(ctx, conn, "DELETE", f"/api/v1/namespaces/{ns}",
                                    timeout_s=90)))
        for sa, role_arn in ((_SA_OK, arn_ok), (_SA_BAD, arn_bad)):
            _k8s_json(ctx, conn, "POST", f"/api/v1/namespaces/{ns}/serviceaccounts",
                      body={"apiVersion": "v1", "kind": "ServiceAccount",
                            "metadata": {"name": sa,
                                         "annotations": {"eks.amazonaws.com/role-arn": role_arn}}})

        admitted_ok, finished_ok, text_ok, sec_ok = _run_pod(
            ctx, conn, ns, _SA_OK,
            _pod_manifest(_SA_OK, _SA_OK, _IMAGE, _SCRIPT_OK,
                          {"AWS_REGION": ctx.region, "AWS_DEFAULT_REGION": ctx.region,
                           "BUCKET": bucket, "KEY": _KEY_OK, "PAYLOAD": _PAYLOAD_OK}),
        )

        # (1) The IRSA admission mutation really happened, and it is IRSA -- not Pod Identity.
        env_ok = {e["name"]: e["value"] for e in admitted_ok["spec"]["containers"][0]["env"]}
        assert env_ok.get(_ROLE_ENV) == arn_ok, (
            f"the admitted pod's {_ROLE_ENV} is {env_ok.get(_ROLE_ENV)!r}, not the role its "
            f"ServiceAccount annotation named ({arn_ok!r}); the IRSA webhook did not translate the "
            f"annotation. admitted env was {sorted(env_ok)!r}"
        )
        assert env_ok.get(_TOKEN_ENV) == _TOKEN_MOUNT + "/token", (
            f"the admitted pod's {_TOKEN_ENV} is {env_ok.get(_TOKEN_ENV)!r}, not a path under the "
            f"projected IRSA token mount {_TOKEN_MOUNT!r}"
        )

        # (2) The projected volume's audience is sts.amazonaws.com. This single field is what
        #     distinguishes IRSA from EKS Pod Identity, whose audience is pods.eks.amazonaws.com.
        audiences = [
            source["serviceAccountToken"]["audience"]
            for volume in admitted_ok["spec"]["volumes"] if volume["name"] == _TOKEN_VOLUME
            for source in volume["projected"]["sources"]
            if "serviceAccountToken" in source
        ]
        assert audiences == [_STS_AUDIENCE_CLAIM], (
            f"the projected {_TOKEN_VOLUME!r} volume has audiences {audiences!r}, not "
            f"[{_STS_AUDIENCE_CLAIM!r}]; volumes={admitted_ok['spec']['volumes']!r}"
        )
        mounts = {m["name"]: m for m in admitted_ok["spec"]["containers"][0]["volumeMounts"]}
        assert mounts[_TOKEN_VOLUME]["mountPath"] == _TOKEN_MOUNT, (
            f"the IRSA token volume is mounted at {mounts[_TOKEN_VOLUME]['mountPath']!r}, not "
            f"{_TOKEN_MOUNT!r}, so {_TOKEN_ENV} points at nothing"
        )
        assert mounts[_TOKEN_VOLUME]["readOnly"] is True, (
            f"the IRSA token mount is writable: {mounts[_TOKEN_VOLUME]!r}"
        )

        # (3) The pod ran and produced all three sections.
        assert finished_ok["status"]["phase"] == "Succeeded", (
            f"the OK pod ended {finished_ok['status']['phase']!r}: {finished_ok['status']!r}"
        )
        assert set(sec_ok) == {"TOKENFILE", "WHOAMI", "PUT"}, (
            f"the OK pod produced sections {sorted(sec_ok)!r}; full log {text_ok!r}"
        )

        # (4) A real JWT was projected into the container's filesystem.
        assert sec_ok["TOKENFILE"][1] == "0", (
            f"the OK pod could not read {_TOKEN_ENV}: rc={sec_ok['TOKENFILE'][1]!r} "
            f"{sec_ok['TOKENFILE'][0]!r}"
        )
        assert int(sec_ok["TOKENFILE"][0].strip()) > 500, (
            f"the projected token is only {sec_ok['TOKENFILE'][0].strip()!r} bytes; a signed RS256 "
            f"ServiceAccount JWT is ~1.2 KB, so this is not a real token"
        )

        # (5) The exchange happened INSIDE the container. The pod's own
        #     identity is a session of role A, which it can only be if STS verified the projected
        #     token's signature against the registered provider's JWKS and matched its `sub`.
        assert sec_ok["WHOAMI"][1] == "0", (
            f"the OK pod could not call sts:GetCallerIdentity at all (rc={sec_ok['WHOAMI'][1]!r}), "
            f"so no credential reached it: {sec_ok['WHOAMI'][0]!r}"
        )
        caller = json.loads(sec_ok["WHOAMI"][0])
        want_prefix = f"arn:aws:sts::{account}:assumed-role/{role_ok}/"
        assert caller["Arn"].startswith(want_prefix), (
            f"the OK pod is running as {caller['Arn']!r}, not a web-identity session of "
            f"{want_prefix!r}"
        )
        assert caller["Account"] == account, f"the pod's session is in another account: {caller!r}"

        # (6) Positive control: the check reads the exact bytes back through S3.
        assert sec_ok["PUT"][1] == "0", (
            f"the OK pod's PutObject failed: rc={sec_ok['PUT'][1]!r} {sec_ok['PUT'][0]!r}"
        )
        landed = s3.get_object(Bucket=bucket, Key=_KEY_OK)["Body"].read().decode("utf-8")
        assert landed == _PAYLOAD_OK, (
            f"S3 holds {landed!r} at {_KEY_OK!r}, want {_PAYLOAD_OK!r}"
        )

        admitted_bad, finished_bad, text_bad, sec_bad = _run_pod(
            ctx, conn, ns, _SA_BAD,
            _pod_manifest(_SA_BAD, _SA_BAD, _IMAGE, _SCRIPT_BAD,
                          {"AWS_REGION": ctx.region, "AWS_DEFAULT_REGION": ctx.region,
                           "BUCKET": bucket, "KEY": _KEY_BAD, "PAYLOAD": _PAYLOAD_BAD}),
        )

        # (7) The BAD pod was mutated identically -- same webhook, same audience, its own role.
        env_bad = {e["name"]: e["value"] for e in admitted_bad["spec"]["containers"][0]["env"]}
        assert env_bad.get(_ROLE_ENV) == arn_bad, (
            f"the BAD pod's {_ROLE_ENV} is {env_bad.get(_ROLE_ENV)!r}, not {arn_bad!r}"
        )
        assert env_bad.get(_TOKEN_ENV) == env_ok.get(_TOKEN_ENV), (
            f"the two pods got different token paths ({env_bad.get(_TOKEN_ENV)!r} vs "
            f"{env_ok.get(_TOKEN_ENV)!r}), so more than the trust condition differs"
        )

        # (8) The token WAS projected and IS full-sized. The refusal is
        #     the trust policy's `sub` condition and nothing else -- not a missing token, not a
        #     webhook that skipped this pod.
        assert sec_bad["TOKENFILE"][1] == "0", (
            f"the BAD pod could not read its token file either (rc={sec_bad['TOKENFILE'][1]!r}), "
            f"so the refusal below is not attributable to the sub condition"
        )
        assert int(sec_bad["TOKENFILE"][0].strip()) > 500, (
            f"the BAD pod's projected token is only {sec_bad['TOKENFILE'][0].strip()!r} bytes, so "
            f"the refusal could be a malformed token rather than the sub condition"
        )

        # (9) Refused at the STS exchange, naming the operation.
        assert sec_bad["WHOAMI"][1] != "0", (
            f"the BAD pod assumed a role whose trust condition names "
            f"{_SA_NEVER!r}, a ServiceAccount that does not exist: {sec_bad['WHOAMI'][0]!r}"
        )
        assert "AccessDenied" in sec_bad["WHOAMI"][0], (
            f"the BAD pod's refusal did not carry the AccessDenied error code: "
            f"{sec_bad['WHOAMI'][0]!r}"
        )
        assert "Not authorized to perform sts:AssumeRoleWithWebIdentity" in sec_bad["WHOAMI"][0], (
            f"the BAD pod was refused, but not at the web-identity exchange: "
            f"{sec_bad['WHOAMI'][0]!r} -- the check's claim is specifically that STS evaluates the "
            f"token's sub claim against the role's trust condition"
        )

        # (10) The container exited 0 in phase Succeeded, so the
        #      denial is an authorization decision and not a crashed or evicted container.
        assert finished_bad["status"]["phase"] == "Succeeded", (
            f"the BAD pod ended {finished_bad['status']['phase']!r}, so its refusal cannot be "
            f"attributed to the trust condition: {finished_bad['status']!r}"
        )
        assert (finished_bad["status"]["containerStatuses"][0]["state"]["terminated"]["exitCode"]
                == 0), (
            f"the BAD pod's container exited non-zero: "
            f"{finished_bad['status']['containerStatuses'][0]['state']!r}"
        )

        # (11) The bucket holds exactly the OK key.
        keys = _all_keys(s3, bucket)
        assert keys == [_KEY_OK], (
            f"the bucket holds {keys!r}; the denied pod's key {_KEY_BAD!r} must not be there, and "
            f"nothing else should be either"
        )
        assert sec_bad["PUT"][1] != "0", (
            f"the BAD pod's PutObject reported success (rc={sec_bad['PUT'][1]!r}) even though the "
            f"key is absent: {sec_bad['PUT'][0]!r}"
        )

        # (12) Addressing the denied key directly -- not just listing -- gets
        #      the exact 404 code, and the denied payload appears in neither pod's output, so no
        #      partial write and no credential leak happened anywhere.
        assert _error_code(lambda: s3.head_object(Bucket=bucket, Key=_KEY_BAD)) == "404", (
            f"HeadObject on the denied key {_KEY_BAD!r} did not return 404; the bucket listing may "
            f"be lagging a write that actually landed"
        )
        assert _PAYLOAD_BAD not in text_ok, (
            f"the denied payload {_PAYLOAD_BAD!r} appears in the OK pod's log: {text_ok!r}"
        )
        assert _PAYLOAD_OK not in text_bad, (
            f"the OK payload {_PAYLOAD_OK!r} appears in the BAD pod's log: {text_bad!r}"
        )

        _k8s(ctx, conn, "DELETE", f"/api/v1/namespaces/{ns}", timeout_s=90)
        _wait_for(
            lambda: _k8s(ctx, conn, "GET", f"/api/v1/namespaces/{ns}")[0],
            lambda code: code == 404,
            timeout_s=_NS_DELETE_TIMEOUT_S,
            interval_s=5,
            desc=f"namespace {ns} deleted",
        )
    except BaseException:
        body_failed.append(True)
        raise
    finally:
        # Verified inline teardown, children before parents, under this check's own budget.
        try:
            _teardown_cluster(eks, cluster_name)
            if provider_arn is not None:
                try:
                    iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn)
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "NoSuchEntity":
                        raise
            for name in (role_ok, role_bad, node_role, cluster_role):
                _delete_role(iam, name)
            _drop_bucket(s3, bucket)
        except BaseException:
            if not body_failed:
                raise

    # Read-only confirmation that nothing billable survived.
    surviving = [n for n in eks.list_clusters().get("clusters", []) if n == cluster_name]
    assert surviving == [], (
        f"the control plane {cluster_name!r} survived the inline teardown: ListClusters still "
        f"reports {surviving!r}, which is a billable leak"
    )
    providers = [
        p["Arn"] for p in iam.list_open_id_connect_providers()["OpenIDConnectProviderList"]
        if issuer_host in p["Arn"]
    ]
    assert providers == [], (
        f"the IAM OIDC provider for {issuer_host!r} survived the inline teardown: {providers!r}"
    )


def _gone_ok(fn):
    """Run a teardown call; a resource the check already deleted in band is done, not a leak."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "NoSuchEntity"):
            raise


def _unless_cluster_gone(ctx, name, fn):
    """Run a cluster-scoped teardown unless the cluster is already deleted, which took it along."""
    if _cluster_status(ctx.client("eks"), name) != "GONE":
        fn()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
