"""live-listener-certificate-rotation-swaps-the-presented-leaf-with-no-dropped-request."""
from __future__ import annotations

import datetime
import os
import shutil
import socket
import ssl
import tempfile
import threading
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "live-listener-certificate-rotation-swaps-the-presented-leaf-with-no-dropped-request"
GROUP = "data-plane"
SERVICES = ["acm", "elbv2"]

_THROTTLE_CODES = (
    "ThrottlingException",
    "Throttling",
    "TooManyRequestsException",
    "RequestInProgressException",
)


def _retry_throttle(fn, attempts=7, base_delay=4.0):
    """Retry fn() on throttle codes."""
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


def _poll_until(ctx, probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate(result); RAISE on deadline (never return the last value)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _crypto():
    """Lazily import `cryptography`; a missing package raises ImportError to the runner."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    return x509, hashes, serialization, rsa, NameOID


def _subject(cn):
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
    """A self-signed RSA-2048 CA. It signs BOTH leaves, so the client's trust store is
    unchanged across the rotation and only the LEAF can explain a difference."""
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
    """A server certificate signed by `issuer_key`, with a DNS SAN list and its own key."""
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


def _two_default_subnets(ec2, *, ctx):
    """Two default subnets in two AZs. An absent default VPC is a FAIL."""
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    assert vpcs, "this account has no shared network VPC, so no internet-facing ALB can be provisioned"
    vpc_id = vpcs[0]["VpcId"]
    by_az = {}
    for page in ec2.get_paginator("describe_subnets").paginate(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]},
                     {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]):
        for subnet in page["Subnets"]:
            by_az.setdefault(subnet["AvailabilityZone"], subnet["SubnetId"])
    azs = sorted(by_az)
    assert len(azs) >= 2, (
        f"an application load balancer needs subnets in two AZs; the run's shared network {vpc_id!r} "
        f"offers {by_az!r}"
    )
    return vpc_id, [by_az[azs[0]], by_az[azs[1]]]


def _listener_certificate_arns(elb, listener_arn):
    """Every certificate ARN on a listener, following the Marker pages."""
    arns, marker = [], None
    while True:
        kwargs = {"ListenerArn": listener_arn}
        if marker:
            kwargs["Marker"] = marker
        page = _retry_throttle(lambda kw=dict(kwargs): elb.describe_listener_certificates(**kw))
        arns.extend(cert["CertificateArn"] for cert in page["Certificates"])
        marker = page.get("NextMarker")
        if not marker:
            return sorted(arns)


def _client_context(trust_pem, tmpdir):
    """A verifying client context trusting ONLY `trust_pem`, hostname checking ON. Shared by the
    foreground probes and the background requester, so both grade the same trust decision."""
    trust_path = os.path.join(tmpdir, "alb-trust.pem")
    with open(trust_path, "wb") as handle:
        handle.write(trust_pem)
    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_ctx.load_verify_locations(cafile=trust_path)
    client_ctx.check_hostname = True
    client_ctx.verify_mode = ssl.CERT_REQUIRED
    return client_ctx


def _one_request(client_ctx, address, sni_host):
    """One verified HTTPS GET / -> {'status', 'body', 'peer_der', 'version'}; raises on failure."""
    request = (f"GET / HTTP/1.1\r\nHost: {sni_host}\r\n"
               f"Connection: close\r\nUser-Agent: sim2real-xsvc-rotation\r\n\r\n").encode()
    with socket.create_connection(address, timeout=15) as raw:
        with client_ctx.wrap_socket(raw, server_hostname=sni_host) as tls:
            peer_der = tls.getpeercert(binary_form=True)
            version = tls.version()
            tls.sendall(request)
            body = b""
            while True:
                chunk = tls.recv(8192)
                if not chunk:
                    break
                body += chunk
    head, _sep, payload = body.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n")[0].decode(errors="replace")
    return {"status": status_line, "body": payload, "peer_der": peer_der, "version": version}


def _wait_for_serving(ctx, client_ctx, address, sni_host, *, timeout_s, description):
    """Poll until the load balancer answers a VERIFIED HTTPS request at all; expiry is a FAIL."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return _one_request(client_ctx, address, sni_host)
        except (OSError, ssl.SSLError) as exc:
            last = f"{type(exc).__name__}: {exc}"
            time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(
        f"{description}: {address[0]!r} never answered a verified HTTPS request within "
        f"{timeout_s}s. Last error: {last}"
    )


class _Requester:
    """A background client that keeps issuing verified HTTPS requests and records EVERY outcome.

    Only a client connected across the change can say whether a request was dropped."""

    def __init__(self, client_ctx, address, sni_host):
        self._ctx = client_ctx
        self._address = address
        self._sni = sni_host
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.ok = 0
        self.serials = []
        self.failures = []
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def _loop(self):
        x509m, _h, _s, _r, _n = _crypto()
        while not self._stop.is_set():
            try:
                result = _one_request(self._ctx, self._address, self._sni)
            except (OSError, ssl.SSLError) as exc:
                with self._lock:
                    self.failures.append(f"{type(exc).__name__}: {exc}")
                continue
            serial = x509m.load_der_x509_certificate(result["peer_der"]).serial_number
            with self._lock:
                if result["status"].endswith("200 OK"):
                    self.ok += 1
                else:
                    self.failures.append(f"HTTP {result['status']!r}")
                self.serials.append(serial)
            self._stop.wait(0.5)

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=60)

    def snapshot(self):
        with self._lock:
            return self.ok, list(self.serials), list(self.failures)



@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:e2e", "dp:endpoint",
      "plane:data")
def run(ctx) -> None:
    """Replacing the default certificate on a LIVE ALB HTTPS listener swaps the leaf clients are
    presented without dropping a request from a client polling throughout; the listener then holds
    only the new certificate, and ACM InUseBy moves from the old certificate to the new one.

    Reference: https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_ModifyListener.html
    Reference: https://docs.aws.amazon.com/acm/latest/APIReference/API_CertificateDetail.html
    """
    acm = ctx.client("acm")
    elb = ctx.client("elbv2")
    ec2 = ctx.client("ec2")

    uid = ctx.unique_name("sim2real-xsvc-rot-")
    host = f"{uid}.example.com"
    nonce = f"sim2real-xsvc-rotation-{uid}"

    root, root_key = _root_ca(f"root-{uid}")
    leaf_old, key_old = _leaf(host, [host], f"root-{uid}", root_key)
    leaf_new, key_new = _leaf(host, [host], f"root-{uid}", root_key)
    assert leaf_old.serial_number != leaf_new.serial_number, (
        "the two leaves must have distinct serials or the rotation is unobservable"
    )

    def _import(leaf, key):
        arn = _retry_throttle(lambda: acm.import_certificate(
            Certificate=_pem(leaf), PrivateKey=_key_pem(key), CertificateChain=_pem(root),
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        ))["CertificateArn"]

        def _delete():
            # An in-use certificate cannot be deleted and the listener's release lags its own
            # delete, so this is a bounded retry that REPORTS a leak rather than hiding it.
            for _ in range(24):
                try:
                    acm.delete_certificate(CertificateArn=arn)
                    return
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "ResourceInUseException":
                        raise
                    time.sleep(5)
            raise RuntimeError(f"acm certificate still in use, not deleted: {arn}")

        ctx.on_cleanup(_delete)
        _poll_until(
            ctx, lambda: _retry_throttle(
                lambda: acm.describe_certificate(CertificateArn=arn))["Certificate"]["Status"],
            lambda status: status == "ISSUED",
            timeout_s=_budget_s(ctx, 120), interval_s=1,
            description=f"the imported certificate {arn} reaching ISSUED",
        )
        return arn

    old_arn = _import(leaf_old, key_old)
    new_arn = _import(leaf_new, key_new)

    vpc_id, subnet_ids = _two_default_subnets(ec2, ctx=ctx)
    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-xsvc-rot-sg-"),
        Description="sim2real-xsvc acm certificate rotation on a live listener",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group",
                            "Tags": [{"Key": "sim2real", "Value": CHECK}]}])["GroupId"]

    def _delete_sg():
        # The ALB's ENIs outlive DeleteLoadBalancer by up to a minute; until they are gone the
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
                                      "Description": "sim2real-xsvc rotation probe"} for c in ctx.ingress_cidrs()]}])

    balancer = _retry_throttle(lambda: elb.create_load_balancer(
        Name=ctx.unique_name("sim2real-xsvc-rl-")[:32].rstrip("-"), Subnets=subnet_ids,
        SecurityGroups=[sg_id], Scheme="internet-facing", Type="application",
        Tags=[{"Key": "sim2real", "Value": CHECK}]))["LoadBalancers"][0]
    lb_arn, lb_dns = balancer["LoadBalancerArn"], balancer["DNSName"]
    lb_address = ctx.endpoint_host(lb_dns, 443)

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

    listener_arn = _retry_throttle(lambda: elb.create_listener(
        LoadBalancerArn=lb_arn, Protocol="HTTPS", Port=443,
        Certificates=[{"CertificateArn": old_arn}],
        DefaultActions=[{"Type": "fixed-response",
                         "FixedResponseConfig": {"StatusCode": "200",
                                                 "ContentType": "text/plain",
                                                 "MessageBody": nonce}}],
    ))["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: elb.delete_listener(ListenerArn=listener_arn))

    # (1) The listener starts out holding exactly the OLD certificate.
    before = _listener_certificate_arns(elb, listener_arn)
    assert before == [old_arn], (
        f"the listener must start with exactly the old certificate; "
        f"DescribeListenerCertificates returned {before!r}, expected {[old_arn]!r}"
    )

    _poll_until(
        ctx, lambda: _retry_throttle(lambda: elb.describe_load_balancers(
            LoadBalancerArns=[lb_arn]))["LoadBalancers"][0]["State"]["Code"],
        lambda code: code == "active",
        timeout_s=_budget_s(ctx, 420), interval_s=2,
        description="the load balancer reaching state 'active'",
    )

    tmpdir = tempfile.mkdtemp(prefix="sim2real-xsvc-rotation-")
    ctx.on_cleanup(lambda: shutil.rmtree(tmpdir, ignore_errors=True))
    client_ctx = _client_context(_pem(root), tmpdir)
    x509m, _h, serialization, _r, _n = _crypto()

    # (2) POSITIVE CONTROL: the load balancer terminates TLS with the OLD leaf and serves.
    first = _wait_for_serving(
        ctx, client_ctx, lb_address, host, timeout_s=_budget_s(ctx, 180),
        description="the HTTPS listener beginning to serve with the pre-rotation certificate")
    assert first["status"].endswith("200 OK"), (
        f"the pre-rotation HTTPS request returned {first['status']!r}, expected a 200")
    assert first["body"].strip() == nonce.encode(), (
        f"the listener served {first['body'].strip()!r}, expected the fixed-response nonce "
        f"{nonce.encode()!r}"
    )
    presented_before = x509m.load_der_x509_certificate(first["peer_der"]).serial_number
    assert presented_before == leaf_old.serial_number, (
        f"before the rotation the load balancer must present the OLD leaf: it presented serial "
        f"{presented_before:x}, expected {leaf_old.serial_number:x}"
    )

    # (3) Start the side channel: a client that keeps asking across the rotation.
    requester = _Requester(client_ctx, lb_address, host)
    ctx.on_cleanup(requester.stop)
    requester.start()
    # Let the requester establish a baseline BEFORE the mutation, bounded by a demonstrated
    # condition (its own successful request count), never by a bare sleep.
    _poll_until(
        ctx, requester.snapshot,
        lambda snap: snap[0] >= 2 or bool(snap[2]),
        timeout_s=_budget_s(ctx, 60), interval_s=1,
        description="the background requester completing two pre-rotation requests",
    )
    baseline_ok, _serials, baseline_failures = requester.snapshot()
    assert not baseline_failures, (
        f"the background requester failed BEFORE the rotation, so nothing after it can be "
        f"attributed: {baseline_failures[:3]!r}"
    )

    # (4) THE MUTATION: replace the listener's default certificate, live.
    _retry_throttle(lambda: elb.modify_listener(
        ListenerArn=listener_arn, Certificates=[{"CertificateArn": new_arn}]))

    # (5) Terminal read at the CONSUMER's data plane, through a different operation than the
    #     mutation: a real client is now presented the NEW leaf.
    def _presented_serial():
        try:
            result = _one_request(client_ctx, lb_address, host)
        except (OSError, ssl.SSLError) as exc:
            return f"<handshake: {type(exc).__name__}: {exc}>"
        return x509m.load_der_x509_certificate(result["peer_der"]).serial_number

    _poll_until(
        ctx, _presented_serial,
        lambda serial: serial == leaf_new.serial_number,
        timeout_s=_budget_s(ctx, 180), interval_s=1,
        description=(
            f"the listener presenting the rotated-in leaf (serial "
            f"{leaf_new.serial_number:x}) instead of the old one "
            f"({leaf_old.serial_number:x})"
        ),
    )

    # (6) The swap is STABLE, not flapping: five consecutive handshakes all present the new
    #     leaf, and the DER matches byte for byte.
    new_der = leaf_new.public_bytes(serialization.Encoding.DER)
    for attempt in range(5):
        result = _one_request(client_ctx, lb_address, host)
        assert result["peer_der"] == new_der, (
            f"handshake {attempt + 1} of 5 after the rotation presented "
            f"{x509m.load_der_x509_certificate(result['peer_der']).serial_number:x}, expected "
            f"the rotated-in leaf {leaf_new.serial_number:x} -- the swap must be stable, not "
            f"alternating"
        )
        assert result["body"].strip() == nonce.encode(), (
            f"handshake {attempt + 1} of 5 served {result['body'].strip()!r}, expected the "
            f"nonce {nonce.encode()!r}"
        )

    # (7) THE DISCRIMINATOR: nothing was dropped while the certificate changed underneath. The
    #     requester keeps running until it has its request floor and has seen the new leaf.
    side_deadline = time.monotonic() + _budget_s(ctx, 60)
    while time.monotonic() < side_deadline:
        side_ok, side_serials, side_failures = requester.snapshot()
        if side_failures or (side_ok >= 5 and leaf_new.serial_number in side_serials):
            break
        time.sleep(1)
    requester.stop()
    total_ok, serials, failures = requester.snapshot()
    if not (failures or (total_ok >= 5 and leaf_new.serial_number in serials)) and _budget_spent(ctx):
        raise TimeoutError("the background requester reaching its request floor and the rotated-in leaf: the run budget ended first; not graded")
    assert not failures, (
        f"rotating an ALB's certificate must not drop a request: the background client recorded "
        f"{len(failures)} failure(s) across {total_ok} successes -- first three: "
        f"{failures[:3]!r}"
    )
    # Zero failures over zero requests cannot fail, so the floor is asserted explicitly.
    assert total_ok >= 5, (
        f"the zero-dropped-requests claim needs a real request population: the background "
        f"client completed only {total_ok} requests (baseline was {baseline_ok}) across the "
        f"rotation window"
    )
    # And the side channel must have OBSERVED the change, not merely survived it.
    assert leaf_old.serial_number in serials and leaf_new.serial_number in serials, (
        f"the background client must have seen both leaves across the rotation; it saw "
        f"{sorted(set(serials))!r} (old {leaf_old.serial_number:x}, new "
        f"{leaf_new.serial_number:x})"
    )
    assert set(serials) <= {leaf_old.serial_number, leaf_new.serial_number}, (
        f"the background client was presented a certificate this check never imported: "
        f"{sorted(set(serials) - {leaf_old.serial_number, leaf_new.serial_number})!r}"
    )

    # (8) The consumer's own index agrees: the default certificate was REPLACED, not added to.
    after = _poll_until(
        ctx, lambda: _listener_certificate_arns(elb, listener_arn),
        lambda arns: arns == [new_arn],
        timeout_s=_budget_s(ctx, 120), interval_s=1,
        description="DescribeListenerCertificates reporting exactly the rotated-in certificate",
    )
    assert after == [new_arn], (
        f"after rotation the listener must hold exactly the new certificate; got {after!r}, "
        f"expected {[new_arn]!r}"
    )

    # (9) Second independent observable, at the PRODUCER: the association moved.
    _poll_until(
        ctx, lambda: _retry_throttle(lambda: acm.describe_certificate(
            CertificateArn=new_arn))["Certificate"]["InUseBy"],
        lambda arns: arns == [lb_arn],
        timeout_s=_budget_s(ctx, 300), interval_s=2,
        description="ACM reporting the rotated-in certificate as in use by the load balancer",
    )
    _poll_until(
        ctx, lambda: _retry_throttle(lambda: acm.describe_certificate(
            CertificateArn=old_arn))["Certificate"]["InUseBy"],
        lambda arns: arns == [],
        timeout_s=_budget_s(ctx, 300), interval_s=2,
        description="ACM draining InUseBy for the certificate that was rotated out",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
