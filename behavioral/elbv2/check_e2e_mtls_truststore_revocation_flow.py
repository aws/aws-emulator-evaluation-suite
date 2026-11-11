"""e2e-mtls-truststore-revocation-flow."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
import urllib.request

from behavioral_harness import tags

CHECK = "e2e-mtls-truststore-revocation-flow"
GROUP = "e2e"
SERVICES = ["elbv2"]

_CIDR = "10.92.0.0/16"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "dp:endpoint", "plane:control", "plane:data")
def run(ctx) -> None:
    """An mTLS listener's trust store counts an added CRL, serves its exact bytes, lists the load
    balancer as associated and refuses a same-account shared-association delete; with mutual
    auth off the trust store deletes and is then not found.
    """
    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")
    s3 = ctx.client("s3")
    acm = ctx.client("acm")

    tagspec = lambda kind, name: {  # noqa: E731
        "ResourceType": kind,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{name}-")}],
    }

    tmpdir = tempfile.mkdtemp(prefix="sim2real-elbv2-mtls-")
    ctx.on_cleanup(_safe(lambda: shutil.rmtree(tmpdir, ignore_errors=True)))

    try:
        cert_pem, key_pem = _make_self_signed(tmpdir, "sim2real-mtls-test.example.com")
        crl_pem = _make_crl_with_one_revocation(tmpdir, cert_pem, key_pem)
    except (OSError, subprocess.CalledProcessError) as err:
        raise AssertionError(f"local openssl toolchain could not generate cert/CRL: {err}")

    cert_arn = acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem)["CertificateArn"]
    ctx.on_cleanup(_safe(lambda: acm.delete_certificate(CertificateArn=cert_arn)))

    bucket = ctx.unique_name("sim2real-elbv2-mtls-").lower().replace("_", "-")
    region = ctx.region
    if region == "us-east-1":  # S3 rejects an explicit LocationConstraint of us-east-1 itself
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(_safe(lambda: s3.delete_bucket(Bucket=bucket)))

    ca_key = "ca-bundle.pem"
    s3.put_object(Bucket=bucket, Key=ca_key, Body=cert_pem)
    ctx.on_cleanup(_safe(lambda: s3.delete_object(Bucket=bucket, Key=ca_key)))
    crl_key = "revocation.crl"
    s3.put_object(Bucket=bucket, Key=crl_key, Body=crl_pem)
    ctx.on_cleanup(_safe(lambda: s3.delete_object(Bucket=bucket, Key=crl_key)))

    vpc_id = ec2.create_vpc(CidrBlock=_CIDR, TagSpecifications=[tagspec("vpc", "vpc")])["Vpc"]["VpcId"]
    ctx.on_cleanup(_safe(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    azs = [
        a["ZoneName"]
        for a in ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
            "AvailabilityZones"
        ][:2]
    ]
    if len(azs) < 2:
        raise AssertionError("region does not expose 2 available AZs for ALB subnets")
    subnet_ids = []
    for i, az in enumerate(azs):
        sn = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.92.{i}.0/24", AvailabilityZone=az,
            TagSpecifications=[tagspec("subnet", f"subnet-{i}")],
        )["Subnet"]
        subnet_ids.append(sn["SubnetId"])
        ctx.on_cleanup(_safe(lambda sid=sn["SubnetId"]: _delete_net(ec2, "delete_subnet", SubnetId=sid)))

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-mtls-sg-"), Description="alb sg", VpcId=vpc_id,
        TagSpecifications=[tagspec("security-group", "sg")],
    )["GroupId"]
    ctx.on_cleanup(_safe(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id)))
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": _CIDR}]}],
    )

    lb_arn = elbv2.create_load_balancer(
        Name=ctx.unique_name("sim2real-mtls-alb-"), Subnets=subnet_ids, SecurityGroups=[sg_id],
        Scheme="internal", Type="application",
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(_safe(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)))
    _poll_until(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]["State"]["Code"],
        lambda code: code == "active", timeout_s=180, interval_s=5,
    )

    listener_arn = elbv2.create_listener(
        LoadBalancerArn=lb_arn, Protocol="HTTPS", Port=443, Certificates=[{"CertificateArn": cert_arn}],
        DefaultActions=[{"Type": "fixed-response", "FixedResponseConfig": {"StatusCode": "200", "ContentType": "text/plain"}}],
    )["Listeners"][0]["ListenerArn"]

    ts_arn = elbv2.create_trust_store(
        Name=ctx.unique_name("sim2real-ts-"), CaCertificatesBundleS3Bucket=bucket, CaCertificatesBundleS3Key=ca_key,
    )["TrustStores"][0]["TrustStoreArn"]
    ctx.on_cleanup(_safe(lambda: elbv2.delete_trust_store(TrustStoreArn=ts_arn)))

    status = _poll_until(
        lambda: elbv2.describe_trust_stores(TrustStoreArns=[ts_arn])["TrustStores"][0]["Status"],
        lambda s: s == "ACTIVE", timeout_s=180, interval_s=5,
    )
    assert status == "ACTIVE", f"trust store never became ACTIVE, last status={status!r}"

    elbv2.modify_listener(
        ListenerArn=listener_arn, MutualAuthentication={"Mode": "verify", "TrustStoreArn": ts_arn}
    )
    mutual_auth = elbv2.describe_listeners(ListenerArns=[listener_arn])["Listeners"][0]["MutualAuthentication"]
    assert mutual_auth["Mode"] == "verify"
    assert mutual_auth["TrustStoreArn"] == ts_arn

    elbv2.modify_listener_attributes(
        ListenerArn=listener_arn,
        Attributes=[{"Key": "routing.http.request.x_amzn_mtls_clientcert_subject.header_name", "Value": "X-Sim2Real-Mtls-Subject"}],
    )
    attrs = {a["Key"]: a["Value"] for a in elbv2.describe_listener_attributes(ListenerArn=listener_arn)["Attributes"]}
    assert attrs.get("routing.http.request.x_amzn_mtls_clientcert_subject.header_name") == "X-Sim2Real-Mtls-Subject"

    before_revoked = elbv2.describe_trust_stores(TrustStoreArns=[ts_arn])["TrustStores"][0]["TotalRevokedEntries"]
    revocation = elbv2.add_trust_store_revocations(
        TrustStoreArn=ts_arn,
        RevocationContents=[{"S3Bucket": bucket, "S3Key": crl_key, "RevocationType": "CRL"}],
    )["TrustStoreRevocations"][0]
    revocation_id = revocation["RevocationId"]

    after_revoked = _poll_until(
        lambda: elbv2.describe_trust_stores(TrustStoreArns=[ts_arn])["TrustStores"][0]["TotalRevokedEntries"],
        lambda n: n > before_revoked,
        timeout_s=120,
        interval_s=5,
    )
    assert after_revoked > before_revoked, "TotalRevokedEntries did not increase after AddTrustStoreRevocations"

    revocations = elbv2.describe_trust_store_revocations(TrustStoreArn=ts_arn)["TrustStoreRevocations"]
    assert any(r["RevocationId"] == revocation_id for r in revocations)

    content = elbv2.get_trust_store_revocation_content(TrustStoreArn=ts_arn, RevocationId=revocation_id)
    location_url = content["Location"]
    _url, _route = ctx.endpoint_route(location_url)
    with urllib.request.urlopen(urllib.request.Request(_url, headers=_route), timeout=10) as resp:
        body = resp.read()
    assert resp.status == 200
    assert body == crl_pem, "revocation content fetched from the presigned Location did not match the uploaded CRL bytes"

    # The associated resource is the owning load balancer's ARN, not the listener ARN.
    associations = elbv2.describe_trust_store_associations(TrustStoreArn=ts_arn)["TrustStoreAssociations"]
    assert any(a["ResourceArn"] == lb_arn for a in associations), (
        f"load balancer {lb_arn} not found in trust store associations {associations}"
    )

    code, message = _error(
        lambda: elbv2.delete_shared_trust_store_association(TrustStoreArn=ts_arn, ResourceArn=listener_arn)
    )
    assert code == "DeleteAssociationSameAccount", f"expected DeleteAssociationSameAccount, got {code!r}"
    expected_message = (
        f"Cannot remove the association because the trust store ARN '{ts_arn}' and resource ARN "
        f"'{listener_arn}' belong to the same account"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    associations_after_reject = elbv2.describe_trust_store_associations(TrustStoreArn=ts_arn)["TrustStoreAssociations"]
    assert any(a["ResourceArn"] == lb_arn for a in associations_after_reject), (
        "association was removed despite the rejected DeleteSharedTrustStoreAssociation call"
    )

    elbv2.modify_listener(ListenerArn=listener_arn, MutualAuthentication={"Mode": "off"})
    mutual_auth_after = elbv2.describe_listeners(ListenerArns=[listener_arn])["Listeners"][0]["MutualAuthentication"]
    assert mutual_auth_after["Mode"] == "off"

    # Dropping the listener's mutual-auth reference can lag briefly behind the
    # ModifyListener response, so bound-retry the delete rather than treating
    # a transient TrustStoreInUse as a hard failure.
    def _try_delete_ts():
        try:
            elbv2.delete_trust_store(TrustStoreArn=ts_arn)
            return True
        except Exception as err:
            resp = getattr(err, "response", None)
            if resp and resp.get("Error", {}).get("Code") == "TrustStoreInUse":
                return False
            raise

    deleted = _poll_until(_try_delete_ts, lambda ok: ok is True, timeout_s=90, interval_s=5)
    assert deleted is True, "trust store deletion still rejected as in-use long after mutual auth was turned off"
    ts_gone_code, ts_gone_message = _error(lambda: elbv2.describe_trust_stores(TrustStoreArns=[ts_arn]))
    assert ts_gone_code == "TrustStoreNotFound", f"expected TrustStoreNotFound, got {ts_gone_code!r}"
    assert ts_gone_message == f"Trust store ARN '{ts_arn}' not found", (
        f"expected the exact not-found message for {ts_arn}, got {ts_gone_message!r}"
    )


#: Already-gone answers of the deletes this check's teardowns make; in-use answers are retried.
_GONE = frozenset({
    "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound", "InvalidGroup.NotFound",
    "InvalidInternetGatewayID.NotFound", "Gateway.NotAttached", "InvalidRouteTableID.NotFound",
    "InvalidAssociationID.NotFound", "InvalidInstanceID.NotFound", "LoadBalancerNotFound",
    "TargetGroupNotFound", "ListenerNotFound", "TrustStoreNotFound", "ResourceNotFoundException",
    "NoSuchBucket", "NoSuchKey",
})
_IN_USE = frozenset({"ResourceInUse", "ResourceInUseException", "DependencyViolation"})


def _safe(fn):
    """Teardown call: an already-gone resource counts as deleted, an in-use one is retried every
    2 s, anything else raises."""
    def _wrapped():
        from botocore.exceptions import ClientError

        deadline = time.monotonic() + 180.0
        while True:
            try:
                fn()
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code in _GONE:
                    return
                if code not in _IN_USE or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    return _wrapped


def _error(fn):
    """Return (code, message) of the service error fn raises; raise AssertionError if it succeeds."""
    try:
        result = fn()
    except Exception as err:
        resp = getattr(err, "response", None)
        if resp is None:
            raise
        error = resp.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        if predicate(value):
            return value
        time.sleep(interval_s)
        value = probe()
    return value


def _make_self_signed(tmpdir: str, cn: str) -> tuple[bytes, bytes]:
    key_path = f"{tmpdir}/key.pem"
    cert_path = f"{tmpdir}/cert.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key_path, "-out", cert_path,
            "-days", "2", "-nodes", "-subj", f"/CN={cn}",
            "-addext", "basicConstraints=critical,CA:true",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign,digitalSignature",
        ],
        check=True, capture_output=True,
    )
    with open(cert_path, "rb") as f:
        cert_pem = f.read()
    with open(key_path, "rb") as f:
        key_pem = f.read()
    return cert_pem, key_pem


def _make_crl_with_one_revocation(tmpdir: str, cert_pem: bytes, key_pem: bytes) -> bytes:
    """Build a CRL from the CA that revokes one throwaway leaf certificate, so
    the trust store's revoked-entry counters actually move off zero (an empty
    CRL revokes nothing and TotalRevokedEntries would legitimately stay 0).
    """
    cert_path = f"{tmpdir}/ca-cert.pem"
    key_path = f"{tmpdir}/ca-key.pem"
    with open(cert_path, "wb") as f:
        f.write(cert_pem)
    with open(key_path, "wb") as f:
        f.write(key_pem)
    index_path = f"{tmpdir}/index.txt"
    open(index_path, "w").close()
    crlnumber_path = f"{tmpdir}/crlnumber"
    with open(crlnumber_path, "w") as f:
        f.write("01\n")
    serial_path = f"{tmpdir}/serial"
    with open(serial_path, "w") as f:
        f.write("01\n")
    new_certs_dir = f"{tmpdir}/newcerts"
    os.makedirs(new_certs_dir, exist_ok=True)
    cnf_path = f"{tmpdir}/openssl.cnf"
    with open(cnf_path, "w") as f:
        f.write(
            "[ ca ]\n"
            "default_ca = CA_default\n\n"
            "[ CA_default ]\n"
            f"dir = {tmpdir}\n"
            f"database = {index_path}\n"
            f"crlnumber = {crlnumber_path}\n"
            f"serial = {serial_path}\n"
            f"new_certs_dir = {new_certs_dir}\n"
            f"certificate = {cert_path}\n"
            f"private_key = {key_path}\n"
            "default_md = sha256\n"
            "default_days = 2\n"
            "default_crl_days = 30\n"
            "unique_subject = no\n"
            "policy = policy_anything\n\n"
            "[ policy_anything ]\n"
            "commonName = supplied\n"
        )

    # Issue a throwaway leaf cert signed by the CA, then immediately revoke it
    # -- this is the one entry that must show up in the CRL / revoked counts.
    leaf_key_path = f"{tmpdir}/leaf-key.pem"
    leaf_csr_path = f"{tmpdir}/leaf.csr"
    leaf_cert_path = f"{tmpdir}/leaf-cert.pem"
    subprocess.run(
        [
            "openssl", "req", "-newkey", "rsa:2048", "-keyout", leaf_key_path, "-out", leaf_csr_path,
            "-nodes", "-subj", "/CN=sim2real-mtls-revoked-leaf.example.com",
        ],
        check=True, capture_output=True,
    )
    subprocess.run(
        [
            "openssl", "ca", "-config", cnf_path, "-in", leaf_csr_path, "-out", leaf_cert_path,
            "-batch", "-notext", "-days", "2",
        ],
        check=True, capture_output=True,
    )
    subprocess.run(
        ["openssl", "ca", "-config", cnf_path, "-revoke", leaf_cert_path, "-crl_reason", "keyCompromise"],
        check=True, capture_output=True,
    )

    crl_path = f"{tmpdir}/revocation.crl"
    subprocess.run(
        ["openssl", "ca", "-config", cnf_path, "-gencrl", "-out", crl_path],
        check=True, capture_output=True,
    )
    with open(crl_path, "rb") as f:
        return f.read()


# A load balancer, endpoint, cluster, function or instance deletes asynchronously: its ENIs stay
# in the subnet / security group, so an immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc
# fails with DependencyViolation. Wait (bounded) for the ENIs to go and retry inside that window.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
