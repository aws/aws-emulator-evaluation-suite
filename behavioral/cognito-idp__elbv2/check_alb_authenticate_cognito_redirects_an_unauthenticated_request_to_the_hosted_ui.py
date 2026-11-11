"""alb-authenticate-cognito-redirects-an-unauthenticated-request-to-the-hosted-ui."""
from __future__ import annotations

import datetime
import os
import shutil
import socket
import ssl
import tempfile
import time
import urllib.parse

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "alb-authenticate-cognito-redirects-an-unauthenticated-request-to-the-hosted-ui"
GROUP = "data-plane"
SERVICES = ["cognito-idp", "elbv2"]

_TAG_VALUE = CHECK[:250]
_SCOPE = "openid email"


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
    "cap:c5",
)
def run(ctx) -> None:
    """An ALB authenticate-cognito rule redirects an unauthenticated (or forged-cookie) HTTPS call
    to the hosted UI with matching client_id, redirect_uri and scope; a deny rule answers 401 and a
    rule with no auth action serves 200.

    Reference: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-authenticate-users.html
    """
    cog = ctx.client("cognito-idp")
    acm = ctx.client("acm")
    elb = ctx.client("elbv2")
    ec2 = ctx.client("ec2")

    uid = ctx.unique_name("sim2real-xsvc-cipalb-")
    host = f"{uid}.example.com"
    nonce = f"sim2real-xsvc-nonce-{uid}"

    # --- the certificate the HTTPS listener needs, minted here and imported ---
    root, root_key = _root_ca(f"root-{uid}")
    leaf, leaf_key = _leaf(host, [host], f"root-{uid}", root_key)
    cert_arn = _retry_throttle(lambda: acm.import_certificate(
        Certificate=_pem(leaf), PrivateKey=_key_pem(leaf_key), CertificateChain=_pem(root),
        Tags=[{"Key": "sim2real:managed", "Value": "true"},
              {"Key": "sim2real", "Value": _TAG_VALUE}]))["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_certificate(acm, cert_arn))
    _poll_until(
        ctx,
        lambda: acm.describe_certificate(CertificateArn=cert_arn)["Certificate"],
        lambda d: d.get("Status") == "ISSUED",
        timeout_s=_budget_s(ctx, 120), interval_s=1,
        description="the imported certificate reaches ISSUED",
    )

    # --- its own VPC: a freshly provisioned account may have no default VPC, and an ALB needs
    # public subnets in two AZs.
    vpc_id, subnet_ids, sg_id = _public_vpc(ctx, ec2)

    lb = elb.create_load_balancer(
        Name=ctx.unique_name("sim2real-cipalb-")[:32].rstrip("-"), Subnets=subnet_ids,
        SecurityGroups=[sg_id], Scheme="internet-facing", Type="application",
        Tags=[{"Key": "sim2real:managed", "Value": "true"},
              {"Key": "sim2real", "Value": _TAG_VALUE}])["LoadBalancers"][0]
    lb_arn, lb_dns = lb["LoadBalancerArn"], lb["DNSName"]
    ctx.on_cleanup(lambda: _delete_load_balancer(elb, lb_arn))

    # --- the user pool, its app client and its hosted-UI domain ---
    pool = cog.create_user_pool(
        PoolName=ctx.unique_name("sim2real-xsvc-cip-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"},
    )["UserPool"]
    pool_id, pool_arn = pool["Id"], pool["Arn"]
    ctx.on_cleanup(lambda _p=pool_id: _delete_user_pool(cog, _p))

    domain_prefix = ctx.unique_name("sim2real-xsvc-cipalb-")[:63].rstrip("-").lower()
    cog.create_user_pool_domain(Domain=domain_prefix, UserPoolId=pool_id)
    ctx.on_cleanup(
        lambda _d=domain_prefix, _p=pool_id: cog.delete_user_pool_domain(
            Domain=_d, UserPoolId=_p
        )
    )
    described_domain = _poll_until(
        ctx,
        lambda: cog.describe_user_pool_domain(Domain=domain_prefix)["DomainDescription"],
        lambda d: d.get("Status") == "ACTIVE",
        timeout_s=_budget_s(ctx, 300), interval_s=1,
        description=f"the user pool domain {domain_prefix} reaches ACTIVE",
    )
    assert described_domain.get("Domain") == domain_prefix, (
        f"DescribeUserPoolDomain must echo the prefix {domain_prefix!r}, got "
        f"{described_domain.get('Domain')!r}"
    )

    # The ALB builds redirect_uri from the incoming request's Host header, not its own DNS name.
    callback = f"https://{host}/oauth2/idpresponse"
    client = cog.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-xsvc-cip-client-"),
        GenerateSecret=True, AllowedOAuthFlows=["code"],
        AllowedOAuthFlowsUserPoolClient=True, AllowedOAuthScopes=_SCOPE.split(),
        CallbackURLs=[callback], SupportedIdentityProviders=["COGNITO"],
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]
    client_id = client["ClientId"]
    ctx.on_cleanup(
        lambda _p=pool_id, _c=client_id: cog.delete_user_pool_client(UserPoolId=_p, ClientId=_c)
    )

    def _auth_action(on_unauthenticated: str) -> dict:
        return {
            "Type": "authenticate-cognito", "Order": 1,
            "AuthenticateCognitoConfig": {
                "UserPoolArn": pool_arn, "UserPoolClientId": client_id,
                "UserPoolDomain": domain_prefix, "Scope": _SCOPE,
                "OnUnauthenticatedRequest": on_unauthenticated,
            },
        }

    def _serve_nonce(order: int | None = None) -> dict:
        action = {
            "Type": "fixed-response",
            "FixedResponseConfig": {"StatusCode": "200", "ContentType": "text/plain",
                                    "MessageBody": nonce},
        }
        if order is not None:
            action["Order"] = order
        return action

    listener_arn = elb.create_listener(
        LoadBalancerArn=lb_arn, Protocol="HTTPS", Port=443,
        Certificates=[{"CertificateArn": cert_arn}],
        DefaultActions=[_auth_action("authenticate"), _serve_nonce(order=2)],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: elb.delete_listener(ListenerArn=listener_arn))

    deny_rule = elb.create_rule(
        ListenerArn=listener_arn, Priority=1,
        Conditions=[{"Field": "path-pattern", "PathPatternConfig": {"Values": ["/deny*"]}}],
        Actions=[_auth_action("deny"), _serve_nonce(order=2)],
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Rules"][0]["RuleArn"]
    ctx.on_cleanup(lambda: elb.delete_rule(RuleArn=deny_rule))
    open_rule = elb.create_rule(
        ListenerArn=listener_arn, Priority=2,
        Conditions=[{"Field": "path-pattern", "PathPatternConfig": {"Values": ["/open*"]}}],
        Actions=[_serve_nonce()],
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Rules"][0]["RuleArn"]
    ctx.on_cleanup(lambda: elb.delete_rule(RuleArn=open_rule))

    # The rule ELB v2 recorded really names this pool and client — read back before any HTTP.
    recorded = {
        a["Type"]: a
        for a in elb.describe_rules(RuleArns=[deny_rule])["Rules"][0]["Actions"]
    }
    assert "authenticate-cognito" in recorded, (
        f"the deny rule must carry an authenticate-cognito action, DescribeRules reports "
        f"{sorted(recorded)}"
    )
    config = recorded["authenticate-cognito"]["AuthenticateCognitoConfig"]
    assert (config["UserPoolArn"], config["UserPoolClientId"], config["UserPoolDomain"]) == (
        pool_arn, client_id, domain_prefix
    ), (
        f"the recorded action must name the pool, client and domain created here; got "
        f"{config['UserPoolArn']!r}, {config['UserPoolClientId']!r}, "
        f"{config['UserPoolDomain']!r}"
    )
    assert config.get("OnUnauthenticatedRequest") == "deny", (
        f"the deny rule must record OnUnauthenticatedRequest=deny, got "
        f"{config.get('OnUnauthenticatedRequest')!r}"
    )

    state = _poll_until(
        ctx,
        lambda: elb.describe_load_balancers(
            LoadBalancerArns=[lb_arn])["LoadBalancers"][0]["State"]["Code"],
        lambda code: code == "active",
        timeout_s=_budget_s(ctx, 420), interval_s=1,
        description="the load balancer reaches state 'active'",
    )
    assert state == "active", f"expected load balancer state 'active', got {state!r}"

    tmpdir = tempfile.mkdtemp(prefix="sim2real-xsvc-cipalb-")
    ctx.on_cleanup(lambda: shutil.rmtree(tmpdir, ignore_errors=True))
    trust_path = _write_trust(tmpdir, _pem(root))

    # --- positive control FIRST: the rule with no auth action serves, so the data path works ---
    served = _https_request(ctx, lb_dns, host, "/open", trust_path)
    assert served["status"] == 200, (
        f"the rule with no authenticate action must serve 200, got {served['status']} "
        f"{served['reason']!r} — the load balancer data path is broken, so the auth verdicts "
        f"below would not be attributable to the auth action"
    )
    assert served["body"].strip() == nonce.encode(), (
        f"the open rule served {served['body'].strip()!r}, expected the per-run nonce "
        f"{nonce.encode()!r}"
    )

    # --- the authenticate action redirects to the hosted UI, with derived parameters ---
    redirected = _https_request(ctx, lb_dns, host, "/", trust_path)
    assert redirected["status"] == 302, (
        f"an unauthenticated request to an authenticate-cognito rule must be redirected with a "
        f"302, got {redirected['status']} {redirected['reason']!r}"
    )
    location = redirected["headers"].get("location")
    assert location, (
        f"the redirect must carry a Location header; response headers were "
        f"{sorted(redirected['headers'])}"
    )
    parsed = urllib.parse.urlsplit(location)
    assert parsed.scheme == "https", (
        f"the hosted-UI redirect must be https, got {location!r}"
    )
    assert domain_prefix in parsed.netloc, (
        f"the redirect host must be the hosted UI of the domain created here "
        f"({domain_prefix}), got {parsed.netloc!r} from {location!r}"
    )
    assert parsed.path == "/oauth2/authorize", (
        f"the redirect must target the authorization endpoint /oauth2/authorize, got "
        f"{parsed.path!r} from {location!r}"
    )
    query = dict(urllib.parse.parse_qsl(parsed.query))
    assert query.get("client_id") == client_id, (
        f"the redirect must carry the app client id {client_id}, got "
        f"{query.get('client_id')!r}"
    )
    assert query.get("response_type") == "code", (
        f"an ALB authenticate-cognito action uses the authorization-code flow, so response_type "
        f"must be 'code', got {query.get('response_type')!r}"
    )
    assert query.get("redirect_uri") == callback, (
        f"the redirect_uri must echo this request's own Host header back as the registered "
        f"callback {callback}, got {query.get('redirect_uri')!r} — a wrong value here sends the "
        f"code somewhere else"
    )
    assert set((query.get("scope") or "").split()) == set(_SCOPE.split()), (
        f"the redirect must request exactly the configured scope {_SCOPE!r}, got "
        f"{query.get('scope')!r}"
    )
    assert query.get("state"), (
        f"the redirect must carry a state value so the callback can be correlated; query was "
        f"{query!r}"
    )
    cookie_names = {c.split("=", 1)[0].strip() for c in redirected["cookies"]}
    assert any(name.startswith("AWSALBAuthNonce") for name in cookie_names), (
        f"the redirect must set the load balancer's nonce cookie (AWSALBAuthNonce*), cookies set "
        f"were {sorted(cookie_names)}"
    )

    # --- a forged session cookie must not be mistaken for a session ---
    forged = _https_request(
        ctx, lb_dns, host, "/", trust_path,
        cookie="AWSALBAuthSessionCookie-0=sim2real-not-a-real-session",
    )
    assert forged["status"] == 302, (
        f"a request carrying a forged AWSALBAuthSessionCookie-0 must still be redirected to the "
        f"hosted UI, got {forged['status']} {forged['reason']!r} — the cookie is being trusted "
        f"because it is present rather than because it is valid"
    )
    assert forged["body"].strip() != nonce.encode(), (
        f"a forged session cookie reached the target: the response body was the protected "
        f"nonce {nonce!r}"
    )

    # --- the twin, in the same instant: same request, same pool, deny instead of authenticate ---
    denied = _https_request(ctx, lb_dns, host, "/deny", trust_path)
    assert denied["status"] == 401, (
        f"OnUnauthenticatedRequest=deny must answer 401 for the identical unauthenticated "
        f"request, got {denied['status']} {denied['reason']!r}"
    )
    assert denied["body"].strip() != nonce.encode(), (
        f"the deny rule served the protected nonce {nonce!r} instead of refusing"
    )
    assert not any(
        name.startswith("AWSALBAuthNonce") for name in
        {c.split("=", 1)[0].strip() for c in denied["cookies"]}
    ), (
        f"a denied request must not begin an authentication flow, but it set "
        f"{sorted(c.split('=', 1)[0].strip() for c in denied['cookies'])}"
    )


_THROTTLE_CODES = ("ThrottlingException", "Throttling", "TooManyRequestsException",
                   "RequestInProgressException")


def _retry_throttle(fn, attempts=7, base_delay=4.0):
    """Retry fn() on throttling error codes."""
    last = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            last = exc
            time.sleep(base_delay * (i + 1))
    raise last


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(ctx, probe, predicate, *, timeout_s=120, interval_s=3.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result. Raises on
    timeout — never returns the last value."""
    deadline = time.monotonic() + timeout_s
    last_result = None
    while time.monotonic() < deadline:
        last_result = probe()
        if predicate(last_result):
            return last_result
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last_result!r}"
    )


def _crypto():
    """Lazily import `cryptography`; a missing module raises ImportError, the runner's fault."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    return x509, hashes, serialization, rsa, NameOID


def _subject(cn):
    """An X.509 Name. The CN is capped at 64 characters by RFC 5280 / `cryptography`."""
    x509, _h, _s, _r, NameOID = _crypto()
    assert len(cn) <= 64, f"CN {cn!r} is {len(cn)} chars; X.509 caps it at 64"
    return x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "sim2real-xsvc-not-a-real-key"),
    ])


def _pem(cert):
    _x, _h, serialization, _r, _n = _crypto()
    return cert.public_bytes(serialization.Encoding.PEM)


def _key_pem(key):
    """PEM-serialise a key generated moments ago in this process. It is not a credential."""
    _x, _h, serialization, _r, _n = _crypto()
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _rsa_key():
    _x, _h, _s, rsa, _n = _crypto()
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _root_ca(cn):
    """A self-signed RSA-2048 CA, used here as the CLIENT'S ONLY TRUST ANCHOR."""
    x509, hashes, _s, _r, _n = _crypto()
    key = _rsa_key()
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_subject(cn)).issuer_name(_subject(cn))
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False),
            critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def _leaf(cn, sans, issuer_cn, issuer_key):
    """A server certificate signed by `issuer_key`, with a DNS SAN list."""
    x509, hashes, _s, _r, _n = _crypto()
    key = _rsa_key()
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_subject(cn)).issuer_name(_subject(issuer_cn))
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
        .sign(issuer_key, hashes.SHA256())
    )
    return cert, key


def _delete_user_pool(cog, pool_id: str) -> None:
    """Delete the pool with a bounded retry: DeleteUserPool can fail right after
    DeleteUserPoolDomain and DeleteUserPoolClient."""
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            cog.delete_user_pool(UserPoolId=pool_id)
            return
        except ClientError as exc:
            print(f"[LEAK-RETRY] user pool {pool_id} not yet deletable: {exc!r}")
            time.sleep(2)
    raise RuntimeError(f"user pool {pool_id} not deleted after retries")


def _delete_certificate(acm, cert_arn: str) -> None:
    """Delete the certificate with a bounded retry: ACM refuses while a listener still references
    it, and the reference clears asynchronously after the listener goes."""
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            acm.delete_certificate(CertificateArn=cert_arn)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceInUseException":
                raise RuntimeError(
                    f"acm certificate {cert_arn} not deleted: {exc!r}"
                ) from exc
            time.sleep(2)
    raise RuntimeError(f"acm certificate still in use, not deleted: {cert_arn}")


def _delete_load_balancer(elb, lb_arn: str) -> None:
    """Delete the ALB and wait for it to disappear, so the security group and subnets that
    follow in the teardown are not blocked by its ENIs."""
    try:
        elb.delete_load_balancer(LoadBalancerArn=lb_arn)
    except ClientError as exc:
        teardown_code = exc.response.get("Error", {}).get("Code", "")
        if teardown_code not in ("LoadBalancerNotFound",):
            raise RuntimeError(f"load balancer {lb_arn} not deleted: {exc!r}") from exc
        return
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            elb.describe_load_balancers(LoadBalancerArns=[lb_arn])
        except ClientError:
            return
        time.sleep(2)
    raise RuntimeError(f"load balancer {lb_arn} still present after delete")


def _retry_dependency(fn, description: str, timeout_s: float = 300.0) -> None:
    """Retry a teardown step through DependencyViolation while the ALB's ENIs linger."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            fn()
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("DependencyViolation",
                                                     "InvalidGroup.InUse"):
                raise RuntimeError(f"{description} failed: {exc!r}") from exc
            last = exc
            time.sleep(2)
    raise RuntimeError(f"{description} never succeeded within {timeout_s}s: {last!r}")


def _public_vpc(ctx, ec2) -> tuple[str, list[str], str]:
    """Create a VPC with a public subnet in each of two AZs and a security group open on 443;
    built rather than adopted because an account may have no default VPC."""
    def tags_for(kind: str) -> list[dict]:
        return [{
            "ResourceType": kind,
            "Tags": [{"Key": "sim2real:managed", "Value": "true"},
                     {"Key": "sim2real", "Value": _TAG_VALUE}],
        }]

    vpc_id = ec2.create_vpc(
        CidrBlock="10.60.0.0/16", TagSpecifications=tags_for("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(
        lambda: _retry_dependency(lambda: ec2.delete_vpc(VpcId=vpc_id), f"delete vpc {vpc_id}")
    )
    _poll_until(ctx, lambda: ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0],
                lambda v: v.get("State") == "available",
                timeout_s=_budget_s(ctx, 120), interval_s=1, description=f"vpc {vpc_id} available")

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=tags_for("internet-gateway"))["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(
        lambda: _retry_dependency(
            lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id),
            f"delete internet gateway {igw_id}",
        )
    )
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(
        lambda: _retry_dependency(
            lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id),
            f"detach internet gateway {igw_id}",
        )
    )

    zones = [
        z["ZoneName"] for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]},
                     {"Name": "zone-type", "Values": ["availability-zone"]}]
        )["AvailabilityZones"]
    ]
    assert len(zones) >= 2, (
        f"an application load balancer needs subnets in two availability zones; {ctx.region} "
        f"reports {zones!r}"
    )
    subnet_ids = []
    for index, zone in enumerate(sorted(zones)[:2]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.60.{index + 1}.0/24", AvailabilityZone=zone,
            TagSpecifications=tags_for("subnet"))["Subnet"]["SubnetId"]
        ctx.on_cleanup(
            lambda _s=subnet_id: _retry_dependency(
                lambda: ec2.delete_subnet(SubnetId=_s), f"delete subnet {_s}"
            )
        )
        ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
        subnet_ids.append(subnet_id)

    route_table_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=tags_for("route-table"))["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(
        lambda: _retry_dependency(
            lambda: ec2.delete_route_table(RouteTableId=route_table_id),
            f"delete route table {route_table_id}",
        )
    )
    ec2.create_route(RouteTableId=route_table_id, DestinationCidrBlock="0.0.0.0/0",
                     GatewayId=igw_id)
    for subnet_id in subnet_ids:
        association = ec2.associate_route_table(
            RouteTableId=route_table_id, SubnetId=subnet_id)["AssociationId"]
        ctx.on_cleanup(
            lambda _a=association: _retry_dependency(
                lambda: ec2.disassociate_route_table(AssociationId=_a),
                f"disassociate route table association {_a}",
            )
        )

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-xsvc-cipalb-sg-"),
        Description="sim2real-xsvc alb authenticate-cognito probe", VpcId=vpc_id,
        TagSpecifications=tags_for("security-group"))["GroupId"]
    ctx.on_cleanup(
        lambda: _retry_dependency(
            lambda: ec2.delete_security_group(GroupId=sg_id), f"delete security group {sg_id}"
        )
    )
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                        "IpRanges": [{"CidrIp": c,
                                      "Description": "sim2real-xsvc https probe"} for c in ctx.ingress_cidrs()]}])
    return vpc_id, subnet_ids, sg_id


def _write_trust(tmpdir: str, trust_pem: bytes) -> str:
    trust_path = os.path.join(tmpdir, "alb-trust.pem")
    with open(trust_path, "wb") as fh:
        fh.write(trust_pem)
    return trust_path


def _https_request(ctx, dns_name: str, sni_host: str, path: str, trust_path: str, *,
                   cookie: str | None = None, timeout_s: float = 180.0) -> dict:
    """One HTTPS request over a raw TLS socket (so 302s are not followed), trusting only
    `trust_path`; retries connection failures because ALB DNS can lag its `active` state."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=trust_path)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    lines = [f"GET {path} HTTP/1.1", f"Host: {sni_host}", "Connection: close",
             "User-Agent: sim2real-xsvc"]
    if cookie:
        lines.append(f"Cookie: {cookie}")
    request = ("\r\n".join(lines) + "\r\n\r\n").encode()

    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(ctx.endpoint_host(dns_name, 443), timeout=15) as raw:
                with context.wrap_socket(raw, server_hostname=sni_host) as tls:
                    tls.sendall(request)
                    payload = b""
                    while True:
                        chunk = tls.recv(8192)
                        if not chunk:
                            break
                        payload += chunk
            return _parse_http(payload)
        except (OSError, ssl.SSLError) as exc:
            last = f"{type(exc).__name__}: {exc}"
            time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"an HTTPS answer from {dns_name!r} for {path!r}: the run budget ended first; not graded")
    raise AssertionError(
        f"the load balancer {dns_name!r} was active but never answered an HTTPS request for "
        f"{path!r} within {timeout_s}s -- provisioned but unconnectable is a failure, not an "
        f"environment limit. Last error: {last}"
    )


def _parse_http(payload: bytes) -> dict:
    """Split a raw HTTP/1.1 response into status, reason, headers (last wins) and cookies."""
    head, _sep, body = payload.partition(b"\r\n\r\n")
    lines = head.decode(errors="replace").split("\r\n")
    assert lines and lines[0].startswith("HTTP/"), (
        f"the load balancer did not answer with an HTTP status line: {payload[:120]!r}"
    )
    parts = lines[0].split(" ", 2)
    assert len(parts) >= 2 and parts[1].isdigit(), (
        f"unparseable HTTP status line {lines[0]!r}"
    )
    headers: dict[str, str] = {}
    cookies: list[str] = []
    for line in lines[1:]:
        name, _colon, value = line.partition(":")
        key = name.strip().lower()
        if key == "set-cookie":
            cookies.append(value.strip())
        elif key:
            headers[key] = value.strip()
    return {"status": int(parts[1]), "reason": parts[2] if len(parts) > 2 else "",
            "headers": headers, "cookies": cookies, "body": body}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
