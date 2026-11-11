"""acm-alb-https-listener-serves-the-imported-certificate."""
from __future__ import annotations

import datetime
import os
import shutil
import socket
import ssl
import tempfile
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "acm-alb-https-listener-serves-the-imported-certificate"
GROUP = 'data-plane'
SERVICES = ['acm', 'elbv2']

# ===== helpers (self-contained) =====

_THROTTLE_CODES = (
    "ThrottlingException",
    "Throttling",
    "TooManyRequestsException",
    "RequestInProgressException",
)


def _retry_throttle(fn, attempts=7, base_delay=4.0):
    """Retry fn() on throttle codes (test-infra robustness, not a behavioral assertion)."""
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


def _poll_until(probe, predicate, *, timeout_s=120, interval_s=3.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last_result = None
    while time.monotonic() < deadline:
        last_result = probe()
        if predicate(last_result):
            return last_result
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last_result!r}")


def _crypto():
    """Lazily import `cryptography`; a missing package raises ImportError to the runner."""
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
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "sim2real-xsvc-acm-not-a-real-key"),
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


def _delete_retrying(what, fn, **kwargs):
    """Delete an EC2 network object, retrying while the ALB's lingering ENIs still hold it."""
    for _ in range(40):
        try:
            fn(**kwargs)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "DependencyViolation":
                raise
            time.sleep(10)
    raise AssertionError(f"{what} still has dependencies after 400s, not deleted")


def _own_public_subnets(ctx, ec2, name):
    """A VPC this check creates, with an internet gateway and two public subnets in two AZs.

    Every object is tagged and registers its cleanup the moment it exists; nothing in the
    account is assumed to exist beforehand.
    """
    def _tags(kind):
        return [{"ResourceType": kind, "Tags": [{"Key": "sim2real", "Value": CHECK},
                                                {"Key": "Name", "Value": name}]}]

    zones = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]},
                 {"Name": "zone-type", "Values": ["availability-zone"]}])["AvailabilityZones"])
    assert len(zones) >= 2, f"an application load balancer needs two AZs; the region offers {zones!r}"

    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16", TagSpecifications=_tags("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_retrying(f"vpc {vpc_id}", ec2.delete_vpc, VpcId=vpc_id))
    igw_id = ec2.create_internet_gateway(
        TagSpecifications=_tags("internet-gateway"))["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _delete_retrying(f"internet gateway {igw_id}", ec2.delete_internet_gateway,
                                            InternetGatewayId=igw_id))
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(lambda: _delete_retrying(f"internet gateway attachment {igw_id}",
                                            ec2.detach_internet_gateway,
                                            InternetGatewayId=igw_id, VpcId=vpc_id))
    rt_id = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=_tags("route-table"))["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _delete_retrying(f"route table {rt_id}", ec2.delete_route_table,
                                            RouteTableId=rt_id))
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    subnet_ids = []
    for i, zone in enumerate(zones[:2]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.0.{i}.0/24", AvailabilityZone=zone,
            TagSpecifications=_tags("subnet"))["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sn=subnet_id: _delete_retrying(f"subnet {sn}", ec2.delete_subnet,
                                                             SubnetId=sn))
        assoc_id = ec2.associate_route_table(RouteTableId=rt_id, SubnetId=subnet_id)["AssociationId"]
        ctx.on_cleanup(lambda a=assoc_id: ec2.disassociate_route_table(AssociationId=a))
        subnet_ids.append(subnet_id)
    return vpc_id, subnet_ids


def _listener_certificate_arns(elb, listener_arn):
    """Every certificate ARN on a listener, following the Marker pages."""
    arns, marker = [], None
    while True:
        kwargs = {"ListenerArn": listener_arn}
        if marker:
            kwargs["Marker"] = marker
        page = elb.describe_listener_certificates(**kwargs)
        arns.extend(c["CertificateArn"] for c in page["Certificates"])
        marker = page.get("NextMarker")
        if not marker:
            return sorted(arns)


def _https_get(ctx, dns_name, sni_host, trust_pem, tmpdir, timeout_s=120):
    """HTTPS GET / against `dns_name`, verifying the chain against `trust_pem` ONLY.

    Hostname verification is ON and `sni_host` is the imported certificate's SAN, so a successful
    return means the load balancer presented a certificate that chains to our private root and
    matches that name. Bounded retry because an ALB's DNS record can lag its `active` state; an
    expiry is a FAIL ("provisioned but unconnectable"), never a skip.
    """
    trust_path = os.path.join(tmpdir, "alb-trust.pem")
    with open(trust_path, "wb") as fh:
        fh.write(trust_pem)
    cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cctx.load_verify_locations(cafile=trust_path)
    cctx.check_hostname = True
    cctx.verify_mode = ssl.CERT_REQUIRED
    request = (f"GET / HTTP/1.1\r\nHost: {sni_host}\r\n"
               f"Connection: close\r\nUser-Agent: sim2real-xsvc\r\n\r\n").encode()
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(ctx.endpoint_host(dns_name, 443), timeout=15) as raw:
                with cctx.wrap_socket(raw, server_hostname=sni_host) as tls:
                    peer_der = tls.getpeercert(binary_form=True)
                    peer = tls.getpeercert()
                    version = tls.version()
                    tls.sendall(request)
                    body = b""
                    while True:
                        chunk = tls.recv(8192)
                        if not chunk:
                            break
                        body += chunk
            return {"peer_der": peer_der, "peer": peer, "version": version, "raw": body}
        except (ConnectionError, TimeoutError, socket.gaierror, ssl.SSLError) as exc:  # retried, then reported as a FAIL
            last = f"{type(exc).__name__}: {exc}"
            time.sleep(5)
    raise AssertionError(
        f"the load balancer {dns_name!r} was active but never answered an HTTPS request within "
        f"{timeout_s}s -- provisioned but unconnectable is a failure, not an environment limit. "
        f"Last error: {last}"
    )


@tags("axis:happy-path", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """An ALB HTTPS listener presents to a real client exactly the certificate imported into ACM
    (same serial, verified against the private root minted here), terminates TLS with it, and
    serves the per-run fixed-response body."""
    acm = ctx.client("acm")
    elb = ctx.client("elbv2")
    ec2 = ctx.client("ec2")

    uid = ctx.unique_name("sim2real-xsvc-alb-")
    host = f"{uid}.example.com"
    nonce = f"sim2real-xsvc-nonce-{uid}"

    root, root_key = _root_ca(f"root-{uid}")
    leaf, leaf_key = _leaf(host, [host], f"root-{uid}", root_key)
    cert_arn = _retry_throttle(lambda: acm.import_certificate(
        Certificate=_pem(leaf), PrivateKey=_key_pem(leaf_key), CertificateChain=_pem(root),
        Tags=[{"Key": "sim2real", "Value": CHECK}]))["CertificateArn"]

    def _delete_cert():
        for _ in range(24):
            try:
                acm.delete_certificate(CertificateArn=cert_arn)
                return
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceInUseException":
                    raise
                time.sleep(5)
        raise RuntimeError(f"acm certificate still in use, not deleted: {cert_arn}")

    ctx.on_cleanup(_delete_cert)
    _poll_until(
        lambda: acm.describe_certificate(CertificateArn=cert_arn)["Certificate"],
        lambda d: d.get("Status") == "ISSUED",
        timeout_s=120, interval_s=3,
        description="the imported certificate reaches ISSUED",
    )

    vpc_id, subnet_ids = _own_public_subnets(ctx, ec2, ctx.unique_name("sim2real-xsvc-alb-net-"))
    sg_name = ctx.unique_name("sim2real-xsvc-alb-sg-")
    sg_id = ec2.create_security_group(
        GroupName=sg_name, Description="sim2real-xsvc acm alb https listener", VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group",
                            "Tags": [{"Key": "sim2real", "Value": CHECK}]}])["GroupId"]

    def _delete_sg():
        # The ALB's ENIs outlive DeleteLoadBalancer by up to a minute, and until they are gone the
        # group has a DependencyViolation. Bounded retry, then report rather than raise.
        for _ in range(30):
            try:
                ec2.delete_security_group(GroupId=sg_id)
                return
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "DependencyViolation":
                    raise
                time.sleep(10)
        raise RuntimeError(f"security group {sg_id} still has dependent ENIs, not deleted")

    ctx.on_cleanup(_delete_sg)
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                        "IpRanges": [{"CidrIp": c,
                                      "Description": "sim2real-xsvc https probe"} for c in ctx.ingress_cidrs()]}])

    lb = elb.create_load_balancer(
        Name=ctx.unique_name("sim2real-xsvc-lb-")[:32].rstrip("-"), Subnets=subnet_ids,
        SecurityGroups=[sg_id], Scheme="internet-facing", Type="application",
        Tags=[{"Key": "sim2real", "Value": CHECK}])["LoadBalancers"][0]
    lb_arn, lb_dns = lb["LoadBalancerArn"], lb["DNSName"]

    def _delete_lb():
        try:
            elb.delete_load_balancer(LoadBalancerArn=lb_arn)
        except ClientError as exc:
            teardown_code = exc.response.get("Error", {}).get("Code", "")
            if teardown_code not in ("LoadBalancerNotFound",):
                raise RuntimeError(f"load balancer {lb_arn} not deleted: {exc}") from exc
            return
        for _ in range(36):
            try:
                elb.describe_load_balancers(LoadBalancerArns=[lb_arn])
            except ClientError:
                return
            time.sleep(5)
        raise RuntimeError(f"load balancer {lb_arn} still present after delete")

    ctx.on_cleanup(_delete_lb)

    listener_arn = elb.create_listener(
        LoadBalancerArn=lb_arn, Protocol="HTTPS", Port=443,
        Certificates=[{"CertificateArn": cert_arn}],
        DefaultActions=[{"Type": "fixed-response",
                         "FixedResponseConfig": {"StatusCode": "200",
                                                 "ContentType": "text/plain",
                                                 "MessageBody": nonce}}],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: elb.delete_listener(ListenerArn=listener_arn))

    # (1) The association ELB v2 records is exactly the certificate we imported.
    assert _listener_certificate_arns(elb, listener_arn) == [cert_arn], (
        "the listener must hold exactly the imported certificate; DescribeListenerCertificates "
        f"returned {_listener_certificate_arns(elb, listener_arn)!r}"
    )

    state = _poll_until(
        lambda: elb.describe_load_balancers(
            LoadBalancerArns=[lb_arn])["LoadBalancers"][0]["State"]["Code"],
        lambda code: code == "active",
        timeout_s=420, interval_s=10,
        description="the load balancer reaches state 'active'",
    )
    assert state == "active", f"load balancer state is {state!r}"

    tmpdir = tempfile.mkdtemp(prefix="sim2real-xsvc-alb-")
    ctx.on_cleanup(lambda: shutil.rmtree(tmpdir, ignore_errors=True))
    result = _https_get(ctx, lb_dns, host, _pem(root), tmpdir)

    # (2) The load balancer really terminated TLS and served the application response. Verifying
    #     against our private root with check_hostname on means path validation succeeded too.
    assert result["version"] == "TLSv1.2", (
        f"the negotiated TLS version was {result['version']!r}; the default ALB security policy "
        "is measured to negotiate exactly 'TLSv1.2'"
    )
    head, _sep, body = result["raw"].partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n")[0].decode(errors="replace")
    assert status_line.endswith("200 OK"), (
        f"the HTTPS request to {lb_dns!r} returned {status_line!r}, expected a 200"
    )
    assert body.strip() == nonce.encode(), (
        f"the listener served {body.strip()!r}, expected the fixed-response nonce "
        f"{nonce.encode()!r}"
    )
    # (3) The certificate on the wire is the one ACM holds -- identified by serial, then by bytes.
    x509m, _h, serialization, _r, _n = _crypto()
    presented = x509m.load_der_x509_certificate(result["peer_der"])
    assert presented.serial_number == leaf.serial_number, (
        f"the load balancer presented serial {presented.serial_number:x}, but the certificate "
        f"imported into ACM has serial {leaf.serial_number:x}"
    )
    assert result["peer_der"] == leaf.public_bytes(serialization.Encoding.DER), (
        "the DER presented by the load balancer must be the DER imported into ACM, byte for "
        f"byte; got {len(result['peer_der'])} bytes vs "
        f"{len(leaf.public_bytes(serialization.Encoding.DER))}"
    )
    # (4) And the SAN the client verified against is the imported one.
    sans = [v for typ, v in (result["peer"].get("subjectAltName") or ()) if typ == "DNS"]
    assert sans == [host], (
        f"the presented certificate's DNS SANs were {sans!r}, expected exactly [{host!r}]"
    )
    # (5) ACM's own view of the association, from the other side of the boundary.
    in_use = _poll_until(
        lambda: acm.describe_certificate(CertificateArn=cert_arn)["Certificate"]["InUseBy"],
        lambda arns: bool(arns),
        timeout_s=120, interval_s=5,
        description="ACM reports the certificate as in use by the load balancer",
    )
    assert in_use == [lb_arn], (
        f"InUseBy must name exactly the load balancer serving it; got {in_use!r}, expected "
        f"[{lb_arn!r}]"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
