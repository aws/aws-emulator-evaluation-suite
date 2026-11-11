"""irsa-web-identity-rejected-when-the-oidc-provider-is-deregistered."""
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

CHECK = "irsa-web-identity-rejected-when-the-oidc-provider-is-deregistered"
GROUP = 'data-plane-rejected'
SERVICES = ['eks']

_CLUSTER_ROLE_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
# EKS refuses to place a control plane in these AZs. The AZ set is still DERIVED from
# describe_availability_zones -- this only removes the zones EKS itself rejects.
_BAD_AZS = {"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"}
_FIXTURE_TAGS = {"sim2real:managed": "true", "sim2real": "irsa-oidc-provider"}

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

# IAM's federation record is eventually consistent in both directions: a deregistration is not
# instantly visible to STS, and neither is a re-registration. Both are converged on by polling the
# real dependent call, never by a fixed sleep.
_REVOCATION_TIMEOUT_S = 300

_IRSA_AUDIENCE = "sts.amazonaws.com"
_SA = "sim2real-irsa-sa"
_KEY_REGISTERED = "while-registered.txt"
_KEY_RESTORED = "after-re-registration.txt"
_PAYLOAD_REGISTERED = "sim2real-irsa-oidc-registered-5c40a7"
_PAYLOAD_RESTORED = "sim2real-irsa-oidc-restored-2ba9e1"

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
        Description="sim2real irsa-oidc-provider check",
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
    """Deregister the issuer, tolerating a provider this check has already removed itself."""
    try:
        iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _poll_until_refused(fn, want, *, timeout_s, interval_s=2):
    """Poll a call until it is refused with exactly `want`; the deadline IS the assertion.

    IAM exposes no condition to poll for "this federation record has been withdrawn", so the
    observable condition polled here is the dependent call's own verdict. A call that still
    succeeds is not yet converged, and running out of deadline reports the last thing observed.
    """
    deadline = time.monotonic() + timeout_s
    last = "<the call SUCCEEDED>"
    while True:
        try:
            fn()
        except ClientError as exc:
            last = exc.response["Error"].get("Code")
            if last == want:
                return
        assert time.monotonic() < deadline, (
            f"after {timeout_s}s the call was still {last!r}, never the expected {want!r}"
        )
        time.sleep(interval_s)


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
    """A cluster-minted ServiceAccount token buys an IRSA role only while the issuer's IAM OIDC
    provider is registered: after DeleteOpenIDConnectProvider the same token is refused
    InvalidIdentityToken and writes nothing; re-registering restores the exchange."""
    from fidelity_tests_runner import require_tools
    require_tools("aws", "kubectl")

    eks = ctx.client("eks")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    suffix = ctx.unique_name("")[:8].lower()
    cluster_name = f"sim2real-irsa-oidc-{suffix}"
    cluster_role = f"sim2real-irsa-oidc-cr-{suffix}"
    role_name = f"sim2real-irsa-oidc-role-{suffix}"
    bucket = f"sim2real-irsa-oidc-{suffix}"
    namespace = f"sim2real-irsa-oidc-{suffix}"
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
        prefix="sim2real-irsa-oidc-kubeconfig-", suffix=".yaml", delete=False
    )
    kubeconfig.close()
    ctx.on_cleanup(lambda: os.unlink(kubeconfig.name))

    vpc, subnets = _create_network(ctx, "10.62")
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

        # Account-scoped and keyed on the issuer URL, which is unique per cluster -- so this
        # check's own cluster gives it an unshared provider, and deregistering it below cannot
        # disturb a sibling run in the same account.
        provider_arn = iam.create_open_id_connect_provider(
            Url=issuer,
            ClientIDList=[_IRSA_AUDIENCE],
            Tags=[{"Key": k, "Value": v} for k, v in _FIXTURE_TAGS.items()],
        )["OpenIDConnectProviderArn"]
        ctx.on_cleanup(lambda: _delete_provider(iam, provider_arn))

        subject = f"system:serviceaccount:{namespace}:{_SA}"
        role_arn = _create_role(
            ctx, role_name, _irsa_trust(provider_arn, issuer_host, subject)
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
        _run(["kubectl", "create", "namespace", namespace], env, timeout_s=120)
        ctx.on_cleanup(lambda: subprocess.run(
            ["kubectl", "delete", "namespace", namespace, "--wait=false"],
            env=env, capture_output=True, timeout=120))
        _run(["kubectl", "create", "serviceaccount", _SA, "-n", namespace], env, timeout_s=120)
        obj = json.loads(_run(
            ["kubectl", "get", "serviceaccount", _SA, "-n", namespace, "-o", "json"],
            env, timeout_s=120))
        # kubectl against the cluster, asserting the OBJECT state the identity is derived from.
        assert obj["metadata"]["namespace"] == namespace, (
            f"the ServiceAccount kubectl created landed in namespace "
            f"{obj['metadata']['namespace']!r}, not {namespace!r}"
        )
        uid = obj["metadata"]["uid"]

        token = _mint_token(env, namespace, _SA, _IRSA_AUDIENCE)
        claims = _claims(token)
        assert claims["iss"] == issuer, (
            f"the token the cluster minted names issuer {claims['iss']!r}, not the {issuer!r} "
            f"DescribeCluster advertises and the IAM provider is registered for"
        )
        assert claims["sub"] == subject, (
            f"the minted token carries sub {claims['sub']!r}, not the {subject!r} the trust "
            f"condition names"
        )
        assert claims["aud"] == [_IRSA_AUDIENCE], (
            f"the minted token's aud is {claims['aud']!r}, not [{_IRSA_AUDIENCE!r}]"
        )
        assert claims["kubernetes.io"]["serviceaccount"]["uid"] == uid, (
            f"the token's ServiceAccount uid is "
            f"{claims['kubernetes.io']['serviceaccount']['uid']!r}, not the {uid!r} kubectl read "
            f"off the object, so it is not bound to it"
        )

        # THE POSITIVE, while the provider is registered.
        granted = _assume_past_propagation(
            sts, role_arn, token, "sim2real-irsa-registered", "AccessDenied",
            timeout_s=_TRUST_PROPAGATION_S,
        )
        assert granted["SubjectFromWebIdentityToken"] == subject, (
            f"STS reports the federated subject as "
            f"{granted['SubjectFromWebIdentityToken']!r}, not {subject!r}"
        )
        want_prefix = f"arn:aws:sts::{account}:assumed-role/{role_name}/"
        assert granted["AssumedRoleUser"]["Arn"].startswith(want_prefix), (
            f"the federated session is {granted['AssumedRoleUser']['Arn']!r}, not a web-identity "
            f"session of {want_prefix!r}"
        )
        _s3_as(ctx, granted["Credentials"]).put_object(
            Bucket=bucket, Key=_KEY_REGISTERED, Body=_PAYLOAD_REGISTERED.encode("utf-8")
        )
        landed = s3.get_object(Bucket=bucket, Key=_KEY_REGISTERED)["Body"].read().decode("utf-8")
        assert landed == _PAYLOAD_REGISTERED, (
            f"S3 holds {landed!r} at {_KEY_REGISTERED!r}, want {_PAYLOAD_REGISTERED!r}"
        )

        # BREAK EXACTLY ONE THING: deregister the issuer. Nothing about the token, the role, the
        # cluster or the bucket changes.
        iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn)
        registered = [
            p["Arn"] for p in
            iam.list_open_id_connect_providers()["OpenIDConnectProviderList"]
            if p["Arn"] == provider_arn
        ]
        assert registered == [], (
            f"DeleteOpenIDConnectProvider returned but {provider_arn!r} is still listed: "
            f"{registered!r}"
        )

        # THE NEGATIVE. IAM's federation record is eventually consistent, so converge on the
        # refusal with a bounded poll and then assert the exact code once, on its own call.
        _poll_until_refused(
            lambda: _assume(sts, role_arn, token, "sim2real-irsa-deregistered"),
            "InvalidIdentityToken", timeout_s=_REVOCATION_TIMEOUT_S,
        )
        code, message = _error(
            lambda: _assume(sts, role_arn, token, "sim2real-irsa-deregistered")
        )
        assert code == "InvalidIdentityToken", (
            f"the token was refused {code!r} ({message!r}) after its issuer was deregistered; "
            f"real AWS refuses an unregistered issuer with InvalidIdentityToken"
        )
        # The sentence is STS's generic token-validation text, so it does not attribute the refusal;
        # the SEQUENCE does: this token and role were accepted above, one thing changed, and they
        # are accepted again below once it is changed back.
        assert message.strip(), (
            f"STS refused with {code!r} and an EMPTY message ({message!r}); a real refusal always "
            f"carries the token-validation sentence"
        )
        expected = (
            "The web identity token provided could not be validated. See the "
            "AssumeRoleWithWebIdentity documentation for requirements."
        )
        assert message == expected, f"expected the refusal {expected!r}, got {message!r}"

        # EFFECT ABSENT: no session was minted, so nothing could be written -- asserted both by a
        # paginated listing scoped to this check's own bucket and by addressing the key directly.
        assert _all_keys(s3, bucket) == [_KEY_REGISTERED], (
            f"the bucket holds {_all_keys(s3, bucket)!r}; only {_KEY_REGISTERED!r} may be there "
            f"while the issuer is deregistered"
        )
        absent_code, _ = _error(lambda: s3.head_object(Bucket=bucket, Key=_KEY_RESTORED))
        assert absent_code == "404", (
            f"HeadObject on {_KEY_RESTORED!r} returned {absent_code!r}, not 404, so a write landed "
            f"while the issuer was deregistered"
        )
        # The ServiceAccount is untouched: the cluster still mints tokens for it, so the refusal is
        # the missing federation record and not a broken identity source.
        still_mints = _mint_token(env, namespace, _SA, _IRSA_AUDIENCE)
        assert _claims(still_mints)["sub"] == subject, (
            f"the cluster stopped minting the subject {subject!r} after the provider was "
            f"deregistered: {_claims(still_mints)!r}"
        )

        # THE EFFECT RETURNS: re-register the SAME issuer URL. The provider's identity is its URL,
        # so the ARN the role's trust policy already names comes back unchanged.
        reborn = iam.create_open_id_connect_provider(
            Url=issuer,
            ClientIDList=[_IRSA_AUDIENCE],
            Tags=[{"Key": k, "Value": v} for k, v in _FIXTURE_TAGS.items()],
        )["OpenIDConnectProviderArn"]
        assert reborn == provider_arn, (
            f"re-registering {issuer!r} minted {reborn!r}, not the original {provider_arn!r}; the "
            f"role's trust policy still names the original, so the control below would be testing "
            f"a different thing"
        )

        # POSITIVE CONTROL, in the same file and after the negative: the same ServiceAccount, the
        # same role and the same bucket work again, so the refusal above was the registration.
        restored = _assume_past_propagation(
            sts, role_arn, _mint_token(env, namespace, _SA, _IRSA_AUDIENCE),
            "sim2real-irsa-reregistered", "InvalidIdentityToken",
            timeout_s=_REVOCATION_TIMEOUT_S,
        )
        assert restored["SubjectFromWebIdentityToken"] == subject, (
            f"the restored exchange federated {restored['SubjectFromWebIdentityToken']!r}, not "
            f"{subject!r}"
        )
        _s3_as(ctx, restored["Credentials"]).put_object(
            Bucket=bucket, Key=_KEY_RESTORED, Body=_PAYLOAD_RESTORED.encode("utf-8")
        )
        restored_landed = (
            s3.get_object(Bucket=bucket, Key=_KEY_RESTORED)["Body"].read().decode("utf-8")
        )
        assert restored_landed == _PAYLOAD_RESTORED, (
            f"S3 holds {restored_landed!r} at {_KEY_RESTORED!r}, want {_PAYLOAD_RESTORED!r}"
        )
        assert _all_keys(s3, bucket) == sorted([_KEY_REGISTERED, _KEY_RESTORED]), (
            f"the bucket ends holding {_all_keys(s3, bucket)!r}; want exactly the object written "
            f"before the deregistration and the one written after it was undone"
        )
    except BaseException:
        body_failed.append(True)
        raise
    finally:
        try:
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
    providers = [
        p["Arn"] for p in iam.list_open_id_connect_providers()["OpenIDConnectProviderList"]
        if issuer_host in p["Arn"]
    ]
    assert providers == [], (
        f"the IAM OIDC provider for {issuer_host!r} survived the inline teardown: {providers!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
