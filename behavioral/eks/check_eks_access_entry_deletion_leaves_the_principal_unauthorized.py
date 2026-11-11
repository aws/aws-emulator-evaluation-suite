"""eks-access-entry-deletion-leaves-the-principal-unauthorized."""
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

CHECK = "eks-access-entry-deletion-leaves-the-principal-unauthorized"
GROUP = 'access-control'
SERVICES = ['eks']

# The shared cluster fixture. Adopted under a deterministic name; teardown is registered ONLY by the
# check that actually created it.
_SHARED_CLUSTER = "sim2real-ga-eks-shr"
_CLUSTER_ROLE = "sim2real-ga-eks-cluster-role"
_EKS_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
_VIEW_POLICY = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy"
_BAD_AZS = {"us-west-2d", "us-east-1e", "us-east-1f", "ca-central-1d"}
_NODE_TYPE = "t3.medium"
_FIXTURE_TAGS = {"sim2real:managed": "true", "sim2real": "ga-depth-eks"}

_CLUSTER_TIMEOUT_S = 1500
_DELETE_RETRY_TIMEOUT_S = 900
_NODEGROUP_TIMEOUT_S = 900
_DECISION_TIMEOUT_S = 420
_ASSUME_TIMEOUT_S = 120
_PROPAGATION_TIMEOUT_S = 180

_PODS_PATH = "/api/v1/namespaces/default/pods?limit=1"
# HTTP statuses that mean "the API server could not answer right now", never "here is the
# authorization verdict". This suite provokes them on purpose: the concurrency check leaves a
# control-plane logging update in flight, and the API server can answer 429/5xx while it settles.
# ONLY these are retried. A 200 (still authorized) keeps the poll going, and any other status --
# including the 401 this check expects -- falls straight through to the assertion, so no real
# signal can hide behind a retry loop.
_TRANSIENT_STATUSES = frozenset({429, 500, 502, 503, 504})

# A propagation artifact of the revocation itself, never the verdict. DeleteAccessEntry
# removes two separate things -- the RBAC binding the access policy association created, and the
# identity MAPPING that lets aws-iam-authenticator resolve the token to a Kubernetes user -- and
# they are NOT ordered. When the binding goes first the principal still authenticates (the API
# server resolves it to a User and says so) but has no permissions left, so the answer is 403
# Forbidden for a moment, until the mapping disappears too and the answer becomes 401.
#
# On AWS a revocation settles to 401 within seconds, and when the binding goes first a 403
# naming the principal appears for ~1-2 s before it:
#   'pods is forbidden: User "arn:aws:sts::...:assumed-role/<role>/s2rentry" cannot list ... "pods"'
# so the first non-200 status is not the verdict. Excluding 403 here does not widen what is
# asserted: the settled status must still be exactly 401 Unauthorized, so a target that answers
# 403 for the whole budget exhausts _wait_for and FAILS.
_REVOCATION_PROPAGATING_STATUSES = frozenset({403})


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
    """Create-or-reuse the fixture's IAM role and return its ARN.

    IAM is eventually consistent and EKS validates roleArn synchronously, so the freshly
    created ARN may not be visible to EKS yet. The caller retries the operation that consumes
    it (see _create_cluster_with_retry) instead of this helper sleeping.
    """
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
    """CreateCluster validates roleArn synchronously against IAM, and a role created seconds
    earlier may not yet be visible to it -- InvalidParameterException, shape-identical to a
    malformed roleArn. IAM exposes no condition to poll, so the bounded retry at first use is
    the correct handling and exhausting it FAILS the check.
    """
    deadline = time.monotonic() + _PROPAGATION_TIMEOUT_S
    while True:
        try:
            return c.create_cluster(**kwargs)
        except ClientError as exc:
            if (
                exc.response["Error"]["Code"] != "InvalidParameterException"
                or time.monotonic() >= deadline
            ):
                raise
            time.sleep(5)


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
    """Mint the EKS Kubernetes bearer token for *creds* (default: this check's own caller).

    The API server authenticates with the aws-iam-authenticator scheme: the token is
    "k8s-aws-v1." + unpadded base64url of a PRESIGNED sts:GetCallerIdentity URL carrying the
    cluster name as a SIGNED x-k8s-aws-id header, which the API server replays against STS to
    learn WHICH AWS principal is calling. Signing it with a second principal's credentials is
    therefore the only way to make a request the API server attributes to that principal.

    *creds* is the raw STS AssumeRole Credentials block; the token is signed as that principal.
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
    req = urllib.request.Request(
        base.rstrip("/") + path, method=method, data=data, headers=headers
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s, context=ssl_ctx) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _assume(ctx, role_arn):
    """Assume *role_arn* with a bounded retry, because a freshly created role's trust policy is
    eventually consistent and STS reports that as AccessDenied rather than exposing a condition
    to poll."""
    sts = ctx.client("sts")
    deadline = time.monotonic() + _ASSUME_TIMEOUT_S
    while True:
        try:
            # The raw STS Credentials block is returned as-is; _k8s_token signs with it.
            return sts.assume_role(RoleArn=role_arn, RoleSessionName="s2rentry")["Credentials"]
        except ClientError as exc:
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"could not assume {role_arn} within {_ASSUME_TIMEOUT_S}s: {exc}"
                ) from exc
            time.sleep(2)


def _create_access_entry(c, cluster, role_arn):
    """CreateAccessEntry with a bounded retry over the IAM propagation window.

    EKS validates principalArn synchronously against IAM, and a
    role created seconds earlier is not yet visible to it -- the refusal is
    InvalidParameterException "The specified principalArn is invalid: invalid principal", which is
    shape-identical to a genuinely malformed ARN. IAM exposes no condition to poll, so the bounded
    retry at first use of the identity is the correct handling and exhausting it FAILS the check.
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
    """Every access-entry principal on the cluster, fully paginated: the cluster is shared with
    other checks, so a membership assertion off page one can fail for reasons unrelated to
    fidelity."""
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
    """Deleting an access entry revokes Kubernetes access: a second principal that could list
    pods through the API server is answered 401 Unauthorized with a Status carrying no data once
    its entry is deleted, while the cluster creator's token still lists pods."""
    c = ctx.client("eks")
    iam = ctx.client("iam")
    conn = _adopt_or_create_cluster(ctx)
    account = ctx.client("sts").get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-eks-ae-")[:64]
    iam.create_role(
        RoleName=role_name,
        Description="sim2real ga-depth eks access-entry revocation subject",
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
    assert role_arn in _access_entry_principals(c, _SHARED_CLUSTER), (
        f"{role_arn!r} is missing from ListAccessEntries right after CreateAccessEntry"
    )

    creds = _assume(ctx, role_arn)

    # (1) THE BARRIER: wait until the grant demonstrably works. Exhausting this budget is a
    #     FAILURE -- a grant that never takes effect is itself the fidelity defect.
    before_status, before_body = _wait_for(
        lambda: _k8s(ctx, conn, "GET", _PODS_PATH, creds=creds),
        lambda sb: sb[0] == 200,
        timeout_s=_DECISION_TIMEOUT_S,
        interval_s=5,
        desc=f"the view-scoped principal {role_name} can list pods",
    )
    assert before_status == 200, (
        f"the granted principal could not list pods to begin with: {before_status!r} "
        f"{before_body[:400]!r}"
    )
    assert json.loads(before_body)["kind"] == "PodList", (
        f"the granted read did not return a PodList: {before_body[:400]!r}"
    )

    # (2) Break exactly ONE thing: the access entry.
    c.delete_access_entry(clusterName=_SHARED_CLUSTER, principalArn=role_arn)
    assert role_arn not in _access_entry_principals(c, _SHARED_CLUSTER), (
        f"{role_arn!r} is still in ListAccessEntries after DeleteAccessEntry"
    )

    # The dead access entry is unusable, not just absent from the list: a policy can only be
    # associated to a principal that has one.
    try:
        c.associate_access_policy(
            clusterName=_SHARED_CLUSTER,
            principalArn=role_arn,
            policyArn=_VIEW_POLICY,
            accessScope={"type": "cluster"},
        )
        raise AssertionError(
            f"AssociateAccessPolicy on {role_arn!r} succeeded after its access entry was deleted"
        )
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException associating a policy to a deleted access "
            f"entry's principal, got {exc.response['Error']['Code']!r}: {exc}"
        )

    after_status, after_body = _wait_for(
        lambda: _k8s(ctx, conn, "GET", _PODS_PATH, creds=creds),
        lambda sb: sb[0] != 200
        and sb[0] not in _TRANSIENT_STATUSES
        and sb[0] not in _REVOCATION_PROPAGATING_STATUSES,
        timeout_s=_DECISION_TIMEOUT_S,
        interval_s=5,
        desc=(
            "the revoked principal's refusal to SETTLE (a 403 here means the RBAC binding is "
            "already gone but the identity mapping has not propagated yet -- see "
            "_REVOCATION_PROPAGATING_STATUSES)"
        ),
    )
    assert after_status == 401, (
        f"after DeleteAccessEntry the API server answered {after_status!r}, not the 401 real EKS "
        f"returns for an unmapped principal: {after_body[:400]!r}"
    )
    refusal = json.loads(after_body)
    assert refusal["kind"] == "Status", (
        f"the refusal body is not a Kubernetes Status object: {refusal!r}"
    )
    assert refusal["reason"] == "Unauthorized", f"{refusal!r}"
    assert refusal["code"] == 401, f"{refusal!r}"

    # (3) THE EFFECT IS ABSENT: the refusal leaks no pod data.
    assert "items" not in refusal, (
        f"the revoked principal's request was refused with {after_status} but still returned "
        f"data: {refusal!r}"
    )

    # (4) POSITIVE CONTROL, same file, same path: the cluster creator's token still works, which
    #     is what proves the 401 above is this principal being revoked rather than the API server
    #     having stopped serving.
    control_status, control_body = _k8s(ctx, conn, "GET", _PODS_PATH)
    assert control_status == 200, (
        f"the cluster creator lost access too, so the 401 above proves nothing: "
        f"{control_status!r} {control_body[:400]!r}"
    )
    assert "items" in json.loads(control_body), (
        f"the creator's PodList carries no items key: {control_body[:400]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
