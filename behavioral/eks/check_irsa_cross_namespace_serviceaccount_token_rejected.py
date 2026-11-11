"""irsa-cross-namespace-serviceaccount-token-rejected."""
from __future__ import annotations

import base64
import json
import os
import subprocess
import tempfile
import time
import urllib.parse

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "irsa-cross-namespace-serviceaccount-token-rejected"
GROUP = 'data-plane-rejected'
SERVICES = ['eks']

_CLUSTER_ROLE_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
# EKS refuses to place a control plane in these zone IDs. The AZ set is still DERIVED from
# describe_availability_zones -- this only removes the zones EKS itself rejects.
_BAD_AZS = {"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"}
_FIXTURE_TAGS = {"sim2real:managed": "true", "sim2real": "irsa-scope"}

# CreateCluster reaches ACTIVE in about 7 min with no node group and DeleteCluster completes in
# about 3 min; the budgets below are ~2x margins on those, and their sum stays under the run's
# 1800 s budget so the inline teardown always completes.
_CLUSTER_TIMEOUT_S = 800
_CLUSTER_DELETE_TIMEOUT_S = 500
_DELETE_RETRY_TIMEOUT_S = 300
_NET_DELETE_TIMEOUT_S = 300
# IAM is eventually consistent and exposes no condition to poll for "this trust policy is now
# effective", so the FIRST use of the role is wrapped in a bounded retry on the one code that
# propagation produces. The retry is what makes the check correct.
_TRUST_PROPAGATION_S = 240

_IRSA_AUDIENCE = "sts.amazonaws.com"
# One ServiceAccount NAME, created identically in two namespaces. The role's trust condition names
# the namespace-qualified subject of the first one only, so the second pod identity differs from
# the allowed subject in EXACTLY the namespace segment of `sub`.
_SA = "sim2real-irsa-sa"
_KEY_ALLOWED = "allowed-namespace.txt"
_KEY_DENIED = "denied-namespace.txt"
_KEY_CONTROL = "allowed-namespace-again.txt"
_PAYLOAD_ALLOWED = "sim2real-irsa-ns-allowed-3b71c4"
_PAYLOAD_DENIED = "sim2real-irsa-ns-denied-7e2a08"
_PAYLOAD_CONTROL = "sim2real-irsa-ns-control-91fd6b"

# Marks a failure in which the cluster's Kubernetes API did not do its part: kubectl reports it in
# its own wording ("connection refused", "couldn't get current server API group list"), which
# otherwise reads like a local connection error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


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
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": service},
                       "Action": ["sts:AssumeRole"]}],
    })


def _irsa_trust(provider_arn, issuer_host, subject):
    """A role trust policy federating the cluster's OIDC provider for exactly one subject."""
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


def _create_role(ctx, name, assume_policy, managed_policies=()):
    iam = ctx.client("iam")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=assume_policy,
        Description="sim2real irsa-scope check",
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


def _retry_delete(fn, codes, desc, timeout_s=_NET_DELETE_TIMEOUT_S):
    """Delete, retrying only while the resource is still referenced by something being torn down."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in codes:
                return
            if code != "DependencyViolation":
                raise
            assert time.monotonic() < deadline, (
                f"{desc} was still refused with DependencyViolation after {timeout_s}s: {exc}"
            )
            time.sleep(10)


def _create_network(ctx, cidr_prefix):
    """A VPC of this check's own, with subnets in two EKS-supported availability zones.

    Deliberately not the default VPC: a freshly provisioned account may not have one, and another
    run changing its default subnets would change what this check sees.
    """
    ec2 = ctx.client("ec2")
    tag_list = [{"Key": k, "Value": v} for k, v in _FIXTURE_TAGS.items()]
    zones = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]},
                     {"Name": "zone-type", "Values": ["availability-zone"]},
                     {"Name": "opt-in-status", "Values": ["opt-in-not-required"]}]
        )["AvailabilityZones"]
        if z["ZoneId"] not in _BAD_AZS
    )
    assert len(zones) >= 2, (
        f"EKS needs subnets in >=2 available zones it supports; {ctx.region} offered {zones!r}"
    )
    vpc = ec2.create_vpc(
        CidrBlock=f"{cidr_prefix}.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": tag_list}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: ec2.delete_vpc(VpcId=vpc), ("InvalidVpcID.NotFound",), f"delete vpc {vpc}"))
    # EKS requires DNS support in the cluster VPC; a fresh VPC has hostnames off.
    ec2.modify_vpc_attribute(VpcId=vpc, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc, EnableDnsHostnames={"Value": True})
    igw = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": tag_list}]
    )["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: ec2.delete_internet_gateway(InternetGatewayId=igw),
        ("InvalidInternetGatewayID.NotFound",), f"delete igw {igw}"))
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc),
        ("Gateway.NotAttached", "InvalidInternetGatewayID.NotFound"),
        f"detach igw {igw}"))
    rtb = ec2.describe_route_tables(
        Filters=[{"Name": "vpc-id", "Values": [vpc]},
                 {"Name": "association.main", "Values": ["true"]}]
    )["RouteTables"][0]["RouteTableId"]
    ec2.create_route(RouteTableId=rtb, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    subnets = []
    for index, zone in enumerate(zones[:2]):
        subnet = ec2.create_subnet(
            VpcId=vpc,
            CidrBlock=f"{cidr_prefix}.{index}.0/24",
            AvailabilityZone=zone,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": tag_list}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda s=subnet: _retry_delete(
            lambda: ec2.delete_subnet(SubnetId=s), ("InvalidSubnetID.NotFound",),
            f"delete subnet {s}"))
        subnets.append(subnet)
    return vpc, subnets


def _teardown_network(ctx, vpc, subnets):
    """Delete the VPC estate, children before parents, polled to actually-gone.

    Driven INLINE from the body's `finally` rather than only from ctx.on_cleanup, whose whole chain
    runs on a daemon thread with a 60 s budget that never affects the verdict -- so a teardown
    driven only from there is cut off mid-delete and the check still reports PASS.
    """
    ec2 = ctx.client("ec2")
    for subnet in subnets:
        _retry_delete(lambda s=subnet: ec2.delete_subnet(SubnetId=s),
                      ("InvalidSubnetID.NotFound",), f"delete subnet {subnet}")
    for igw in ec2.describe_internet_gateways(
        Filters=[{"Name": "attachment.vpc-id", "Values": [vpc]}]
    )["InternetGateways"]:
        gid = igw["InternetGatewayId"]
        _retry_delete(lambda g=gid: ec2.detach_internet_gateway(InternetGatewayId=g, VpcId=vpc),
                      ("Gateway.NotAttached", "InvalidInternetGatewayID.NotFound"),
                      f"detach igw {gid}")
        _retry_delete(lambda g=gid: ec2.delete_internet_gateway(InternetGatewayId=g),
                      ("InvalidInternetGatewayID.NotFound",), f"delete igw {gid}")
    _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc), ("InvalidVpcID.NotFound",),
                  f"delete vpc {vpc}")


def _cluster_status(c, name):
    try:
        return c.describe_cluster(name=name)["cluster"]["status"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return "GONE"
        raise


def _create_cluster(ctx, name, role_arn, subnet_ids):
    c = ctx.client("eks")
    deadline = time.monotonic() + _DELETE_RETRY_TIMEOUT_S
    while True:
        try:
            c.create_cluster(
                name=name,
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
            break
        except ClientError as exc:
            # The cluster role IAM has just handed back is not always assumable by EKS yet; retry
            # the real dependent call every 2 s to a bounded deadline.
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


def _teardown_cluster(c, name):
    deadline = time.monotonic() + _DELETE_RETRY_TIMEOUT_S
    while True:
        try:
            c.delete_cluster(name=name)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException":
                raise
            assert time.monotonic() < deadline, (
                f"delete cluster {name} was still refused with ResourceInUseException after "
                f"{_DELETE_RETRY_TIMEOUT_S}s: {exc}"
            )
            time.sleep(15)
    _wait_for(
        lambda: _cluster_status(c, name),
        lambda s: s == "GONE",
        timeout_s=_CLUSTER_DELETE_TIMEOUT_S,
        interval_s=20,
        desc=f"cluster {name} fully deleted",
    )


def _run(cmd, env, *, timeout_s):
    """Run a tool that speaks to the cluster, failing with the data-plane marker."""
    proc = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=timeout_s)
    if proc.returncode != 0:
        raise AssertionError(
            f"{DATAPLANE_MARKER}: {' '.join(cmd)} failed (rc={proc.returncode}): "
            f"{proc.stderr[-600:]!r}"
        )
    return proc.stdout


def _kube_env(ctx, cluster_name, kubeconfig):
    """A subprocess environment holding the check's own credentials and a private kubeconfig.

    ctx.subprocess_env() carries the check's own credentials and strips AWS_PROFILE /
    AWS_ENDPOINT_URL*; a bare os.environ would make kubectl's credential plugin use the
    ambient credential chain instead.
    """
    env = ctx.subprocess_env()
    env["KUBECONFIG"] = kubeconfig
    _run(["aws", "eks", "update-kubeconfig", "--name", cluster_name, "--region", ctx.region],
         env, timeout_s=180)
    return env


def _claims(token):
    """The JWT payload of a ServiceAccount token, decoded structurally."""
    parts = token.split(".")
    assert len(parts) == 3, f"the minted token is not a three-segment JWT: {token[:40]!r}"
    body = parts[1]
    body += "=" * (-len(body) % 4)
    return json.loads(base64.urlsafe_b64decode(body))


def _mint_token(env, namespace, service_account, audience):
    """A ServiceAccount token minted by the cluster's own TokenRequest API, through kubectl."""
    return _run(
        ["kubectl", "create", "token", service_account, "-n", namespace,
         "--audience", audience, "--duration", "1h"],
        env, timeout_s=120,
    ).strip()


def _assume(sts, role_arn, token, session_name):
    return sts.assume_role_with_web_identity(
        RoleArn=role_arn, RoleSessionName=session_name, WebIdentityToken=token
    )


def _assume_past_propagation(sts, role_arn, token, session_name, retry_code, *, timeout_s):
    """AssumeRoleWithWebIdentity, retrying ONLY the one code propagation produces.

    IAM exposes no condition to poll for "this trust policy is now effective", so the bounded
    retry at first use of the permission is what makes the positive correct; it is not a sleep
    standing in for a wait.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return _assume(sts, role_arn, token, session_name)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code != retry_code:
                raise
            assert time.monotonic() < deadline, (
                f"AssumeRoleWithWebIdentity on {role_arn!r} was still refused {code!r} after "
                f"{timeout_s}s: {exc}"
            )
            time.sleep(2)


def _delete_provider(iam, arn):
    """Deregister the issuer, tolerating a provider the inline teardown has already removed."""
    try:
        iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _error(fn):
    """The (code, message) an AWS call is refused with. RAISES if it unexpectedly SUCCEEDS.

    A falsy sentinel here would turn the strongest possible signal -- a target accepting input
    real AWS rejects -- into something that reads like a naming difference.
    """
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message", "")
    raise AssertionError("the call was expected to be refused but it SUCCEEDED")


def _s3_as(ctx, creds):
    """An S3 client carrying ONLY the federated session's credentials."""
    return ctx.client(
        "s3",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _put_with_fresh_credentials(s3, timeout_s=60.0, **kwargs):
    """PutObject with just-issued session credentials, which S3 can answer InvalidAccessKeyId
    for until they propagate; that one code is retried every 2 s, everything else raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return s3.put_object(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidAccessKeyId" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _all_keys(s3, bucket):
    """Every key in the bucket, paginated -- a membership assertion off one page is not a bound."""
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return sorted(keys)


def _drop_bucket(s3, name):
    """Empty and delete the bucket; idempotent, since it runs inline and again as a cleanup."""
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=name):
            stale = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in list(page.get("Versions", [])) + list(page.get("DeleteMarkers", []))
            ]
            if stale:
                s3.delete_objects(Bucket=name, Delete={"Objects": stale})
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


# ===== the check =====


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:native", "plane:data")
def run(ctx) -> None:
    """An IRSA trust policy's `sub` condition is namespace-qualified: a token for the same-named
    ServiceAccount in another namespace is refused AccessDenied at AssumeRoleWithWebIdentity and
    writes nothing, while the allowed namespace's token works before and after."""
    from fidelity_tests_runner import require_tools
    require_tools("aws", "kubectl")

    eks = ctx.client("eks")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    suffix = ctx.unique_name("")[:8].lower()
    cluster_name = f"sim2real-irsa-ns-{suffix}"
    cluster_role = f"sim2real-irsa-ns-cr-{suffix}"
    role_name = f"sim2real-irsa-ns-role-{suffix}"
    bucket = f"sim2real-irsa-ns-{suffix}"
    ns_allowed = f"sim2real-irsa-a-{suffix}"
    ns_denied = f"sim2real-irsa-b-{suffix}"
    provider_arn = None
    vpc = None
    subnets = []
    # Set when an assertion in the body fails, so the inline teardown's own failure cannot mask the
    # assertion failure that caused it. ctx.on_cleanup remains the net for that path.
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

    kubeconfig = tempfile.NamedTemporaryFile(
        prefix="sim2real-irsa-ns-kubeconfig-", suffix=".yaml", delete=False
    )
    kubeconfig.close()
    ctx.on_cleanup(lambda: os.unlink(kubeconfig.name))

    vpc, subnets = _create_network(ctx, "10.61")
    cluster = _create_cluster(ctx, cluster_name, cluster_role_arn, subnets)
    ctx.on_cleanup(lambda: _teardown_cluster(eks, cluster_name))

    try:
        issuer = cluster["identity"]["oidc"]["issuer"]
        issuer_url = urllib.parse.urlsplit(issuer)
        assert issuer_url.scheme in ("http", "https") and issuer_url.hostname, (
            f"the cluster advertises OIDC issuer {issuer!r}, which is not an issuer URL, so "
            f"no IAM OIDC provider can be registered for it"
        )
        issuer_host = issuer.split("://", 1)[1]

        # The IAM OIDC provider is account-scoped and keyed on the issuer URL, which is unique per
        # cluster -- so this check's own cluster gives it an unshared provider with no
        # adopt-vs-create race against a sibling run in the same account.
        provider_arn = iam.create_open_id_connect_provider(
            Url=issuer,
            ClientIDList=[_IRSA_AUDIENCE],
            Tags=[{"Key": k, "Value": v} for k, v in _FIXTURE_TAGS.items()],
        )["OpenIDConnectProviderArn"]
        ctx.on_cleanup(lambda: _delete_provider(iam, provider_arn))

        subject_allowed = f"system:serviceaccount:{ns_allowed}:{_SA}"
        subject_denied = f"system:serviceaccount:{ns_denied}:{_SA}"
        role_arn = _create_role(
            ctx, role_name, _irsa_trust(provider_arn, issuer_host, subject_allowed)
        )
        ctx.on_cleanup(lambda: _delete_role(iam, role_name))
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="s3-one-bucket",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": ["s3:PutObject", "s3:GetObject"],
                               "Resource": f"arn:aws:s3:::{bucket}/*"}],
            }),
        )

        env = _kube_env(ctx, cluster_name, kubeconfig.name)
        uids = {}
        for namespace in (ns_allowed, ns_denied):
            _run(["kubectl", "create", "namespace", namespace], env, timeout_s=120)
            ctx.on_cleanup(lambda n=namespace: subprocess.run(
                ["kubectl", "delete", "namespace", n, "--wait=false"],
                env=env, capture_output=True, timeout=120))
            _run(["kubectl", "create", "serviceaccount", _SA, "-n", namespace],
                 env, timeout_s=120)
            obj = json.loads(_run(
                ["kubectl", "get", "serviceaccount", _SA, "-n", namespace, "-o", "json"],
                env, timeout_s=120))
            # kubectl against the cluster, asserting the OBJECT state the identity is derived from.
            assert obj["metadata"]["name"] == _SA, (
                f"kubectl read back ServiceAccount {obj['metadata']['name']!r} in {namespace!r}, "
                f"not {_SA!r}"
            )
            assert obj["metadata"]["namespace"] == namespace, (
                f"the ServiceAccount kubectl created landed in namespace "
                f"{obj['metadata']['namespace']!r}, not {namespace!r}"
            )
            uids[namespace] = obj["metadata"]["uid"]
        assert uids[ns_allowed] != uids[ns_denied], (
            f"the two namespaces' ServiceAccounts share the UID {uids[ns_allowed]!r}, so they are "
            f"one object and the cross-namespace claim below is untestable"
        )

        token_allowed = _mint_token(env, ns_allowed, _SA, _IRSA_AUDIENCE)
        claims_allowed = _claims(token_allowed)
        assert claims_allowed["iss"] == issuer, (
            f"the token the cluster minted names issuer {claims_allowed['iss']!r}, not the "
            f"{issuer!r} DescribeCluster advertises and the IAM provider is registered for"
        )
        assert claims_allowed["aud"] == [_IRSA_AUDIENCE], (
            f"the minted token's aud is {claims_allowed['aud']!r}, not [{_IRSA_AUDIENCE!r}]"
        )
        assert claims_allowed["sub"] == subject_allowed, (
            f"the token minted in {ns_allowed!r} carries sub {claims_allowed['sub']!r}, not the "
            f"namespace-qualified {subject_allowed!r} the trust condition names"
        )
        assert (claims_allowed["kubernetes.io"]["serviceaccount"]["uid"]
                == uids[ns_allowed]), (
            f"the token's ServiceAccount uid is "
            f"{claims_allowed['kubernetes.io']['serviceaccount']['uid']!r}, not the "
            f"{uids[ns_allowed]!r} kubectl read off the object, so it is not bound to it"
        )

        # THE HEADLINE POSITIVE: the cluster-minted token is exchanged for a session of the role,
        # which STS can only grant by verifying the JWT against the registered provider's JWKS and
        # matching its namespace-qualified `sub`.
        granted = _assume_past_propagation(
            sts, role_arn, token_allowed, "sim2real-irsa-allowed", "AccessDenied",
            timeout_s=_TRUST_PROPAGATION_S,
        )
        assert granted["SubjectFromWebIdentityToken"] == subject_allowed, (
            f"STS reports the federated subject as "
            f"{granted['SubjectFromWebIdentityToken']!r}, not {subject_allowed!r}"
        )
        assert granted["Audience"] == _IRSA_AUDIENCE, (
            f"STS reports audience {granted['Audience']!r}, not {_IRSA_AUDIENCE!r}"
        )
        want_prefix = f"arn:aws:sts::{account}:assumed-role/{role_name}/"
        assert granted["AssumedRoleUser"]["Arn"].startswith(want_prefix), (
            f"the federated session is {granted['AssumedRoleUser']['Arn']!r}, not a "
            f"web-identity session of {want_prefix!r}"
        )

        # POSITIVE CONTROL, off-response and in a second service: the credentials the exchange
        # returned really carry the role's permissions, and the runner's own client reads the bytes.
        _put_with_fresh_credentials(
            _s3_as(ctx, granted["Credentials"]),
            Bucket=bucket, Key=_KEY_ALLOWED, Body=_PAYLOAD_ALLOWED.encode("utf-8"),
        )
        landed = s3.get_object(Bucket=bucket, Key=_KEY_ALLOWED)["Body"].read().decode("utf-8")
        assert landed == _PAYLOAD_ALLOWED, (
            f"S3 holds {landed!r} at {_KEY_ALLOWED!r}, want {_PAYLOAD_ALLOWED!r}"
        )

        token_denied = _mint_token(env, ns_denied, _SA, _IRSA_AUDIENCE)
        claims_denied = _claims(token_denied)

        # BREAK EXACTLY ONE THING, asserted rather than assumed: the second token is the same
        # issuer, the same audience and the same ServiceAccount name, differing ONLY in the
        # namespace segment of `sub`.
        assert claims_denied["sub"] == subject_denied, (
            f"the token minted in {ns_denied!r} carries sub {claims_denied['sub']!r}, not "
            f"{subject_denied!r}"
        )
        assert claims_denied["iss"] == claims_allowed["iss"], (
            f"the two tokens came from different issuers ({claims_denied['iss']!r} vs "
            f"{claims_allowed['iss']!r}), so more than the namespace differs"
        )
        assert claims_denied["aud"] == claims_allowed["aud"], (
            f"the two tokens carry different audiences ({claims_denied['aud']!r} vs "
            f"{claims_allowed['aud']!r}), so more than the namespace differs"
        )
        assert (claims_denied["sub"].split(":")[-1]
                == claims_allowed["sub"].split(":")[-1] == _SA), (
            f"the two subjects name different ServiceAccounts ({claims_denied['sub']!r} vs "
            f"{claims_allowed['sub']!r}); the whole claim is that only the namespace differs"
        )
        assert len(token_denied) > 500, (
            f"the cross-namespace token is only {len(token_denied)} bytes; a signed RS256 "
            f"ServiceAccount JWT is ~1 KB, so the refusal below could be a malformed token "
            f"rather than the namespace in its subject"
        )

        # THE NEGATIVE, with the exact error code and the exchange it was refused at.
        code, message = _error(
            lambda: _assume(sts, role_arn, token_denied, "sim2real-irsa-denied")
        )
        assert code == "AccessDenied", (
            f"the cross-namespace token was refused {code!r} ({message!r}); real AWS refuses the "
            f"web-identity exchange with AccessDenied when the token's sub does not match the "
            f"trust condition"
        )
        assert message == "Not authorized to perform sts:AssumeRoleWithWebIdentity", (
            f"the refusal {message!r} is not the web-identity exchange's refusal, so it cannot be "
            f"attributed to the trust policy's sub condition"
        )

        # EFFECT ABSENT: no session was minted, so no object can exist under the denied key --
        # asserted both by a paginated listing scoped to this check's own bucket and by addressing
        # the key directly, in case the listing lags a write that did land.
        assert _all_keys(s3, bucket) == [_KEY_ALLOWED], (
            f"the bucket holds {_all_keys(s3, bucket)!r}; only {_KEY_ALLOWED!r} may be there, and "
            f"the denied namespace's {_KEY_DENIED!r} must not"
        )
        denied_code, _ = _error(lambda: s3.head_object(Bucket=bucket, Key=_KEY_DENIED))
        assert denied_code == "404", (
            f"HeadObject on the denied key {_KEY_DENIED!r} returned {denied_code!r}, not 404"
        )

        # POSITIVE CONTROL AFTER THE NEGATIVE: the role, the provider and the bucket are all still
        # functional, so the refusal above is the namespace in the subject and nothing else.
        control = _assume(sts, role_arn, _mint_token(env, ns_allowed, _SA, _IRSA_AUDIENCE),
                          "sim2real-irsa-control")
        assert control["SubjectFromWebIdentityToken"] == subject_allowed, (
            f"the control exchange federated {control['SubjectFromWebIdentityToken']!r}, not "
            f"{subject_allowed!r}"
        )
        _put_with_fresh_credentials(
            _s3_as(ctx, control["Credentials"]),
            Bucket=bucket, Key=_KEY_CONTROL, Body=_PAYLOAD_CONTROL.encode("utf-8"),
        )
        control_landed = (
            s3.get_object(Bucket=bucket, Key=_KEY_CONTROL)["Body"].read().decode("utf-8")
        )
        assert control_landed == _PAYLOAD_CONTROL, (
            f"S3 holds {control_landed!r} at {_KEY_CONTROL!r}, want {_PAYLOAD_CONTROL!r}"
        )
        assert _all_keys(s3, bucket) == sorted([_KEY_ALLOWED, _KEY_CONTROL]), (
            f"the bucket ends holding {_all_keys(s3, bucket)!r}; want exactly the two objects the "
            f"allowed subject wrote, and never {_KEY_DENIED!r}"
        )
        assert _PAYLOAD_DENIED not in (landed + control_landed), (
            f"the denied namespace's payload {_PAYLOAD_DENIED!r} reached S3 anyway"
        )
    except BaseException:
        body_failed.append(True)
        raise
    finally:
        try:
            for namespace in (ns_denied, ns_allowed):
                subprocess.run(["kubectl", "delete", "namespace", namespace, "--wait=false"],
                               env=ctx.subprocess_env() | {"KUBECONFIG": kubeconfig.name},
                               capture_output=True, timeout=120)
            _teardown_cluster(eks, cluster_name)
            if provider_arn is not None:
                _delete_provider(iam, provider_arn)
            for name in (role_name, cluster_role):
                _delete_role(iam, name)
            _drop_bucket(s3, bucket)
            _teardown_network(ctx, vpc, subnets)
        except BaseException:
            if not body_failed:
                raise

    # Read-only confirmation that nothing billable survived, paginated.
    surviving = [
        n for page in eks.get_paginator("list_clusters").paginate()
        for n in page.get("clusters", []) if n == cluster_name
    ]
    assert surviving == [], (
        f"the control plane {cluster_name!r} survived the inline teardown: ListClusters still "
        f"reports {surviving!r}, which is a billable leak"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
