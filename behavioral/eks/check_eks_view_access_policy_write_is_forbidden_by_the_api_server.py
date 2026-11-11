"""eks-view-access-policy-write-is-forbidden-by-the-api-server."""
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


CHECK = "eks-view-access-policy-write-is-forbidden-by-the-api-server"
GROUP = 'access-control'
SERVICES = ['eks']

# Shared cluster fixture, adopted under a deterministic name; teardown is registered
# only by the check that actually created it.
_SHARED_CLUSTER = "sim2real-ga-eks-shr"
_CLUSTER_ROLE = "sim2real-ga-eks-cluster-role"
_EKS_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
_VIEW_POLICY = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy"
_BAD_AZS = {"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"}
_NODE_TYPE = "t3.medium"
_FIXTURE_TAGS = {"sim2real:managed": "true", "sim2real": "ga-depth-eks"}

# Absorbs a slow control-plane create on the one run that builds the shared fixture.
_CLUSTER_TIMEOUT_S = 1500
_DELETE_RETRY_TIMEOUT_S = 900
_NODEGROUP_TIMEOUT_S = 900
# Bounds the grant taking effect.
_DECISION_TIMEOUT_S = 420
_ASSUME_TIMEOUT_S = 120
_PROPAGATION_TIMEOUT_S = 180

_PODS_PATH = "/api/v1/namespaces/default/pods?limit=1"
# HTTP statuses meaning "the API server could not answer right now" (e.g. 429/5xx while a
# control-plane update settles), never an authorization verdict. Only these are retried;
# a 201 (write allowed) or 401 (principal not mapped) falls straight through to the assertion.
_TRANSIENT_STATUSES = frozenset({429, 500, 502, 503, 504})
_SESSION = "s2rwrite"


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
        if z["ZoneName"] in offered and z["ZoneId"] not in _BAD_AZS
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

    DeleteCluster can be refused with ResourceInUseException "update in progress" while
    ListUpdates is empty, so the delete itself must be retried, not just its status polled.
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


def _teardown_cluster(c, name):
    """Drain dependents then delete the control plane, polling it to actually gone."""
    try:
        for ng in c.list_nodegroups(clusterName=name).get("nodegroups", []):
            _delete_with_retry(
                lambda ng=ng: c.delete_nodegroup(clusterName=name, nodegroupName=ng),
                f"delete nodegroup {ng}",
            )
            _wait_for(
                lambda ng=ng: _nodegroup_status(c, name, ng),
                lambda s: s == "GONE",
                timeout_s=_NODEGROUP_TIMEOUT_S,
                interval_s=20,
                desc=f"nodegroup {ng} deleted",
            )
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


def _create_cluster_with_retry(c, **kwargs):
    """CreateCluster with a bounded retry over the IAM propagation window.

    EKS validates roleArn synchronously against IAM; a just-created role is refused until visible.
    """
    deadline = time.monotonic() + _PROPAGATION_TIMEOUT_S
    while True:
        try:
            return c.create_cluster(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("InvalidParameterException", "ClientException"):
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"create_cluster kept refusing roleArn {kwargs['roleArn']!r} as invalid "
                    f"after {_PROPAGATION_TIMEOUT_S}s (IAM propagation?): {exc}"
                ) from exc
            time.sleep(2)


def _adopt_or_create_cluster(ctx):
    """Return (endpoint, ca_pem) for the shared ACTIVE cluster; teardown only if we made it."""
    c = ctx.client("eks")
    try:
        _create_cluster_with_retry(
            c,
            name=_SHARED_CLUSTER,
            roleArn=_ensure_role(
                ctx, _CLUSTER_ROLE, "eks.amazonaws.com", [_EKS_CLUSTER_POLICY]
            ),
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
    return cluster["endpoint"], ca_pem


def _k8s_token(ctx, cluster_name, creds=None, *, ttl_s=900):
    """Mint the EKS Kubernetes bearer token signed as *creds* (default: this check's own caller).

    The token is "k8s-aws-v1." + a presigned sts:GetCallerIdentity URL with a signed
    x-k8s-aws-id header; the API server replays it against STS to learn the calling principal.
    """
    override = None
    if creds is not None:
        override = {
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        }
    # A client of its own per cluster, so the signed x-k8s-aws-id header never reaches other calls.
    sts = ctx.client(
        "sts",
        endpoint_url=ctx.service_url(f"https://sts.{ctx.region}.amazonaws.com"),
        config=Config(user_agent_extra=f"k8s-aws-id/{cluster_name}"),
        creds=override,
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


def _k8s(ctx, conn, method, path, *, body=None, creds=None, timeout_s=60):
    """Request the cluster's Kubernetes API server, trusting ONLY the advertised CA."""
    base, ca_pem = conn
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_ctx.check_hostname = True
    ssl_ctx.verify_mode = ssl.CERT_REQUIRED
    ssl_ctx.load_verify_locations(cadata=ca_pem)
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {_k8s_token(ctx, _SHARED_CLUSTER, creds)}",
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


def _assume(ctx, role_arn):
    """Assume *role_arn* with a bounded retry: a new role's trust policy is eventually consistent
    and STS reports that as AccessDenied rather than exposing a condition to poll.
    """
    sts = ctx.client("sts")
    deadline = time.monotonic() + _ASSUME_TIMEOUT_S
    while True:
        try:
            # The raw STS Credentials block is returned as-is; _k8s_token signs with it.
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION)["Credentials"]
        except ClientError as exc:
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"could not assume {role_arn} within {_ASSUME_TIMEOUT_S}s: {exc}"
                ) from exc
            time.sleep(2)


def _create_access_entry(c, cluster, role_arn):
    """CreateAccessEntry with a bounded retry over the IAM propagation window.

    A just-created role is refused as InvalidParameterException "invalid principal" until IAM
    propagates; exhausting the retry fails the check.
    """
    deadline = time.monotonic() + _PROPAGATION_TIMEOUT_S
    while True:
        try:
            return c.create_access_entry(
                clusterName=cluster, principalArn=role_arn, type="STANDARD"
            )
        except ClientError as exc:
            if (
                exc.response["Error"]["Code"] != "InvalidParameterException"
                or time.monotonic() >= deadline
            ):
                raise
            time.sleep(5)

def _access_entry_principals(c, cluster):
    """Every access-entry principal on the cluster, fully paginated."""
    principals = []
    token = None
    while True:
        kwargs = {"clusterName": cluster, "maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        page = c.list_access_entries(**kwargs)
        principals.extend(page.get("accessEntries", []))
        token = page.get("nextToken")
        if not token:
            return principals


def _drop_access_entry(c, cluster, principal_arn):
    try:
        c.delete_access_entry(clusterName=cluster, principalArn=principal_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_role(iam, name):
    for pol in iam.list_attached_role_policies(RoleName=name).get("AttachedPolicies", []):
        iam.detach_role_policy(RoleName=name, PolicyArn=pol["PolicyArn"])
    iam.delete_role(RoleName=name)


def _k8s_json(ctx, conn, method, path, *, body=None, creds=None, expect=(200, 201)):
    status, raw = _k8s(ctx, conn, method, path, body=body, creds=creds)
    assert status in expect, (
        f"{method} {path} on the Kubernetes API returned {status}, expected one of {expect}: "
        f"{raw[:400]!r}"
    )
    return json.loads(raw)


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c5",
    "cap:c7",
)
def run(ctx) -> None:
    """A principal holding only AmazonEKSViewPolicy can list pods, but its namespace CREATE is
    refused 403 with a Status naming its assumed-role ARN and nothing is created, while the
    cluster creator's identical request succeeds: the policy's verb scope is enforced.
    """
    c = ctx.client("eks")
    iam = ctx.client("iam")
    conn = _adopt_or_create_cluster(ctx)
    account = ctx.client("sts").get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-eks-view-")[:64]
    iam.create_role(
        RoleName=role_name,
        Description="sim2real ga-depth eks view-scope subject",
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": "sts:AssumeRole",
            }],
        }),
        Tags=[{"Key": "sim2real:managed", "Value": "true"},
              {"Key": "sim2real", "Value": "ga-depth-eks"}],
    )
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    role_arn = f"arn:aws:iam::{account}:role/{role_name}"

    _create_access_entry(c, _SHARED_CLUSTER, role_arn)
    ctx.on_cleanup(lambda: _drop_access_entry(c, _SHARED_CLUSTER, role_arn))
    c.associate_access_policy(
        clusterName=_SHARED_CLUSTER,
        principalArn=role_arn,
        policyArn=_VIEW_POLICY,
        accessScope={"type": "cluster"},
    )
    associated = c.list_associated_access_policies(
        clusterName=_SHARED_CLUSTER, principalArn=role_arn
    )["associatedAccessPolicies"]
    assert [(a["policyArn"], a["accessScope"]["type"]) for a in associated] == [
        (_VIEW_POLICY, "cluster")
    ], f"the association EKS recorded is not the view policy at cluster scope: {associated!r}"

    creds = _assume(ctx, role_arn)

    # (1) POSITIVE CONTROL and propagation barrier in one: the grant demonstrably works for the
    #     verbs it covers. Exhausting this budget is a FAILURE.
    read_status, read_body = _wait_for(
        lambda: _k8s(ctx, conn, "GET", _PODS_PATH, creds=creds),
        lambda sb: sb[0] == 200,
        timeout_s=_DECISION_TIMEOUT_S,
        interval_s=5,
        desc=f"the view-scoped principal {role_name} can list pods",
    )
    assert json.loads(read_body)["kind"] == "PodList", (
        f"the view-scoped read returned {read_body[:400]!r}, not a PodList"
    )

    # (2) The ONE thing that differs from the accepted call below is who signed it.
    target_ns = ctx.unique_name("sim2real-view-")[:63].lower()
    manifest = {
        "apiVersion": "v1", "kind": "Namespace",
        "metadata": {"name": target_ns, "labels": {"sim2real": "ga-depth-eks"}},
    }
    deadline = time.monotonic() + _DECISION_TIMEOUT_S
    while True:
        write_status, write_body = _k8s(
            ctx, conn, "POST", "/api/v1/namespaces", body=manifest, creds=creds
        )
        if write_status not in _TRANSIENT_STATUSES or time.monotonic() >= deadline:
            break
        time.sleep(5)
    assert write_status == 403, (
        f"a principal holding only AmazonEKSViewPolicy created a namespace: got "
        f"{write_status!r} {write_body[:400]!r}"
    )
    refusal = json.loads(write_body)
    assert refusal["kind"] == "Status", f"the refusal is not a Status object: {refusal!r}"
    assert refusal["reason"] == "Forbidden", f"{refusal!r}"
    assert refusal["code"] == 403, f"{refusal!r}"
    assert refusal["details"]["kind"] == "namespaces", f"{refusal!r}"
    # The API server names the caller's STS assumed-role session, not the access entry's role ARN.
    expected_principal = f"arn:aws:sts::{account}:assumed-role/{role_name}/{_SESSION}"
    assert expected_principal in refusal["message"], (
        f"the API server's refusal does not name the calling principal "
        f"{expected_principal!r}: {refusal['message']!r}"
    )

    # (3) THE EFFECT IS ABSENT: read back with a token that WOULD be allowed to see it.
    missing_status, missing_body = _k8s(ctx, conn, "GET", f"/api/v1/namespaces/{target_ns}")
    assert missing_status == 404, (
        f"the refused create left something behind: GET /api/v1/namespaces/{target_ns} returned "
        f"{missing_status!r} {missing_body[:400]!r}"
    )

    # (4) POSITIVE CONTROL: the byte-identical request from the cluster creator is accepted, so
    #     the 403 above is the access policy's verb scope and nothing else.
    created = _k8s_json(ctx, conn, "POST", "/api/v1/namespaces", body=manifest)
    ctx.on_cleanup(lambda: _k8s(ctx, conn, "DELETE", f"/api/v1/namespaces/{target_ns}",
                                timeout_s=90))
    assert created["metadata"]["name"] == target_ns, f"{created!r}"
    assert _k8s(ctx, conn, "GET", f"/api/v1/namespaces/{target_ns}")[0] == 200, (
        f"the creator's namespace {target_ns!r} is not readable after a 201"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
