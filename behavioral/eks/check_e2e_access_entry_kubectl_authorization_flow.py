"""e2e-access-entry-kubectl-authorization-flow."""
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

CHECK = "e2e-access-entry-kubectl-authorization-flow"
GROUP = "state-machine"
SERVICES = ["eks"]

# A shared cluster adopted under a deterministic name; only the check that created it tears it down.
_SHARED_CLUSTER = "sim2real-ga-eks-shr"
_CLUSTER_ROLE = "sim2real-ga-eks-cluster-role"
_EKS_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
_VIEW_POLICY = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy"
_BAD_AZS = {"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"}
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
# authorization verdict". ONLY these are retried through; any other status -- including the
# ones this check expects -- falls straight through to the assertion.
_TRANSIENT_STATUSES = frozenset({429, 500, 502, 503, 504})

# DeleteAccessEntry removes the identity mapping asynchronously: the GET keeps answering 403 for a
# while before settling to 401. The settled status must still be exactly 401.
_DELETE_PROPAGATING_STATUSES = frozenset({403})


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_for(fn, pred, *, timeout_s, interval_s, desc, ctx=None):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"{desc}: the run budget ended first; not graded")
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
    # IAM is eventually consistent and EKS validates roleArn synchronously; the bounded
    # CreateCluster retry in _adopt_or_create_cluster covers a role not yet visible.
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
    """Retry a delete through ResourceInUseException within a bounded budget: DeleteCluster can be
    refused that way on an ACTIVE cluster with no dependents left and no updates listed."""
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
            time.sleep(3)


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
                interval_s=5,
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
        interval_s=5,
        desc=f"cluster {name} fully deleted",
    )


def _adopt_or_create_cluster(ctx):
    """Return (endpoint, ca_pem) for the shared ACTIVE cluster; teardown only if we made it."""
    c = ctx.client("eks")
    role_arn = _ensure_role(ctx, _CLUSTER_ROLE, "eks.amazonaws.com", [_EKS_CLUSTER_POLICY])
    subnet_ids = _fixture_subnets(ctx)
    deadline = time.monotonic() + _budget_s(ctx, _PROPAGATION_TIMEOUT_S)
    while True:
        try:
            c.create_cluster(
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
            )
            ctx.on_cleanup(lambda: _teardown_cluster(c, _SHARED_CLUSTER))
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceInUseException":
                break
            # A role not yet visible to EKS is refused with InvalidParameterException.
            if code != "InvalidParameterException" or time.monotonic() >= deadline:
                if code == "InvalidParameterException" and _budget_spent(ctx):
                    raise TimeoutError(f"CreateCluster {_SHARED_CLUSTER} past IAM propagation: the run budget ended first; not graded") from exc
                raise
            time.sleep(2)
    cluster = _wait_for(
        lambda: c.describe_cluster(name=_SHARED_CLUSTER)["cluster"],
        lambda cl: cl["status"] in ("ACTIVE", "FAILED"),
        ctx=ctx,
        timeout_s=_budget_s(ctx, _CLUSTER_TIMEOUT_S),
        interval_s=2,
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
    """Mint the EKS bearer token for *creds* (default: this check's caller): "k8s-aws-v1." plus
    unpadded base64url of a presigned GetCallerIdentity URL signing the x-k8s-aws-id header."""
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
    deadline = time.monotonic() + _budget_s(ctx, _ASSUME_TIMEOUT_S)
    while True:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName="s2rflow")["Credentials"]
        except ClientError as exc:
            if time.monotonic() >= deadline:
                if _budget_spent(ctx):
                    raise TimeoutError(f"assuming {role_arn}: the run budget ended first; not graded") from exc
                raise AssertionError(
                    f"could not assume {role_arn} within {_ASSUME_TIMEOUT_S}s: {exc}"
                ) from exc
            time.sleep(2)


def _create_access_entry(ctx, c, cluster, principal_arn):
    """CreateAccessEntry, retried through InvalidParameterException while a new role is not yet
    visible to EKS's synchronous principalArn validation."""
    deadline = time.monotonic() + _budget_s(ctx, _PROPAGATION_TIMEOUT_S)
    while True:
        try:
            return c.create_access_entry(
                clusterName=cluster, principalArn=principal_arn, type="STANDARD"
            )
        except ClientError as exc:
            if (
                exc.response["Error"]["Code"] != "InvalidParameterException"
                or time.monotonic() >= deadline
            ):
                if exc.response["Error"]["Code"] == "InvalidParameterException" and _budget_spent(ctx):
                    raise TimeoutError(f"CreateAccessEntry for {principal_arn} past IAM propagation: the run budget ended first; not graded") from exc
                raise
            time.sleep(2)


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


def _error_code(fn):
    """The error code fn() raises; a success fails the check, it is never a code."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(f"the call succeeded where AWS refuses it: {result!r}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An access entry with AmazonEKSViewPolicy lets the principal list pods at the Kubernetes API;
    after disassociating the policy the same GET is 403 Forbidden, and after deleting the entry 401.

    Reference: https://docs.aws.amazon.com/eks/latest/userguide/access-entries.html
    """
    c = ctx.client("eks")
    iam = ctx.client("iam")
    conn = _adopt_or_create_cluster(ctx)
    account = ctx.client("sts").get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-eks-principal-")[:64]
    iam.create_role(
        RoleName=role_name,
        Description="sim2real ga-depth eks access-entry authorization-flow subject",
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
    principal_arn = f"arn:aws:iam::{account}:role/{role_name}"

    _create_access_entry(ctx, c, _SHARED_CLUSTER, principal_arn)
    ctx.on_cleanup(lambda: _drop_access_entry(c, _SHARED_CLUSTER, principal_arn))

    c.associate_access_policy(
        clusterName=_SHARED_CLUSTER,
        principalArn=principal_arn,
        policyArn=_VIEW_POLICY,
        accessScope={"type": "cluster"},
    )
    associated = c.list_associated_access_policies(
        clusterName=_SHARED_CLUSTER, principalArn=principal_arn
    )["associatedAccessPolicies"]
    assert any(p["policyArn"] == _VIEW_POLICY for p in associated), (
        "associated policy not listed as the effective grant for the principal"
    )

    creds = _assume(ctx, principal_arn)

    # Wait until the grant demonstrably works, so neither withdrawal can be mistaken for
    # "the grant never took effect".
    before_status, before_body = _wait_for(
        lambda: _k8s(ctx, conn, "GET", _PODS_PATH, creds=creds),
        lambda sb: sb[0] == 200,
        ctx=ctx,
        timeout_s=_budget_s(ctx, _DECISION_TIMEOUT_S),
        interval_s=1,
        desc=f"the associated view policy grants {role_name} pod reads at the API server",
    )
    assert before_status == 200, (
        f"the associated policy did not grant a real pod read: {before_status!r} "
        f"{before_body[:400]!r}"
    )
    assert json.loads(before_body)["kind"] == "PodList", (
        f"the granted read did not return a PodList: {before_body[:400]!r}"
    )

    # STEP BACK (1): disassociate the policy. RBAC binding gone; identity mapping survives.
    c.disassociate_access_policy(
        clusterName=_SHARED_CLUSTER, principalArn=principal_arn, policyArn=_VIEW_POLICY
    )
    remaining = c.list_associated_access_policies(
        clusterName=_SHARED_CLUSTER, principalArn=principal_arn
    )["associatedAccessPolicies"]
    assert not any(p["policyArn"] == _VIEW_POLICY for p in remaining), (
        "disassociated policy still listed as a grant"
    )

    mid_status, mid_body = _wait_for(
        lambda: _k8s(ctx, conn, "GET", _PODS_PATH, creds=creds),
        lambda sb: sb[0] != 200 and sb[0] not in _TRANSIENT_STATUSES,
        ctx=ctx,
        timeout_s=_budget_s(ctx, _DECISION_TIMEOUT_S),
        interval_s=1,
        desc="the disassociated principal's pod read to stop succeeding",
    )
    assert mid_status == 403, (
        f"after DisassociateAccessPolicy the API server answered {mid_status!r}, not the 403 "
        f"expected for an authenticated principal with no remaining RBAC permissions: "
        f"{mid_body[:400]!r}"
    )
    mid_refusal = json.loads(mid_body)
    assert mid_refusal["kind"] == "Status", f"the refusal is not a Status object: {mid_refusal!r}"
    assert mid_refusal["reason"] == "Forbidden", f"{mid_refusal!r}"
    assert "items" not in mid_refusal, (
        f"the disassociated principal's request was refused but still returned data: "
        f"{mid_refusal!r}"
    )

    # Still mapped: a byte-identical call from the cluster creator proves the API server itself
    # is healthy, so the 403 above is this principal's RBAC and nothing else.
    control_status, control_body = _k8s(ctx, conn, "GET", _PODS_PATH)
    assert control_status == 200, (
        f"the cluster creator lost access too, so the 403 above proves nothing: "
        f"{control_status!r} {control_body[:400]!r}"
    )

    # STEP BACK (2): delete the access entry itself. The identity mapping is now gone too.
    c.delete_access_entry(clusterName=_SHARED_CLUSTER, principalArn=principal_arn)
    code = _error_code(
        lambda: c.describe_access_entry(clusterName=_SHARED_CLUSTER, principalArn=principal_arn)
    )
    assert code == "ResourceNotFoundException", f"unexpected code after delete: {code}"

    after_status, after_body = _wait_for(
        lambda: _k8s(ctx, conn, "GET", _PODS_PATH, creds=creds),
        lambda sb: sb[0] != 200
        and sb[0] not in _TRANSIENT_STATUSES
        and sb[0] not in _DELETE_PROPAGATING_STATUSES,
        ctx=ctx,
        timeout_s=_budget_s(ctx, _DECISION_TIMEOUT_S),
        interval_s=1,
        desc=(
            "the fully-deleted principal's refusal to SETTLE (a 403 here means RBAC is "
            "already gone but the identity mapping has not propagated yet)"
        ),
    )
    assert after_status == 401, (
        f"after DeleteAccessEntry the API server answered {after_status!r}, not the 401 real "
        f"EKS returns for an unmapped principal: {after_body[:400]!r}"
    )
    after_refusal = json.loads(after_body)
    assert after_refusal["kind"] == "Status", f"{after_refusal!r}"
    assert after_refusal["reason"] == "Unauthorized", f"{after_refusal!r}"
    assert "items" not in after_refusal, (
        f"the unmapped principal's request was refused but still returned data: {after_refusal!r}"
    )

    # POSITIVE CONTROL, same file, same path: the cluster creator's token still works, so the
    # 401 above is this principal losing its mapping and not the API server going dark.
    final_status, final_body = _k8s(ctx, conn, "GET", _PODS_PATH)
    assert final_status == 200, (
        f"the cluster creator lost access too, so the 401 above proves nothing: "
        f"{final_status!r} {final_body[:400]!r}"
    )
    assert "items" in json.loads(final_body), (
        f"the creator's PodList carries no items key: {final_body[:400]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
