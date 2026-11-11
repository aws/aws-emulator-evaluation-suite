"""certificate-register-deregister-lifecycle."""
from __future__ import annotations

import datetime
import secrets
import subprocess
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "certificate-register-deregister-lifecycle"
GROUP = "error-semantics"
SERVICES = ["ds"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterCertificate with Type=ClientCertAuth on a fresh, Active AWS Managed Microsoft AD
    directory is rejected with UnsupportedOperationException, and ListCertificates shows no
    certificate registered before or after the attempt."""
    cert_pem = _generate_self_signed_ca_pem()
    if cert_pem is None:
        raise AssertionError(
            "neither the 'cryptography' Python package nor the 'openssl' CLI is "
            "available in this environment to generate a test CA certificate for "
            "RegisterCertificate; install either to close this gap."
        )

    ds = ctx.client("ds")
    vpc_id, subnet_ids = _create_vpc_with_two_subnets(ctx)
    directory_id = _create_active_microsoft_ad(ctx, ds, vpc_id, subnet_ids)

    # Positive control: the directory and credentials are healthy for certificate operations
    # in general -- an unrelated, always-legal read against the same API surface succeeds.
    initial_certs = ds.list_certificates(DirectoryId=directory_id)["CertificatesInfo"]
    assert initial_certs == [], f"freshly-created directory already lists certificates: {initial_certs!r}"

    code, message, request_id = _error_code_and_message(
        lambda: ds.register_certificate(DirectoryId=directory_id, CertificateData=cert_pem, Type="ClientCertAuth")
    )
    assert code == "UnsupportedOperationException", (
        f"expected RegisterCertificate(Type=ClientCertAuth) against a Managed Microsoft AD "
        f"directory to be rejected with UnsupportedOperationException, got {code!r}: {message!r}"
    )
    assert "not supported for this directory type" in (message or "").lower(), (
        f"expected the specific 'not supported for this Directory Type' refusal, got: {message!r}"
    )
    expected_message = (
        f"Client authentication operations are not supported for this Directory Type. : RequestId: {request_id}"
    )
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    remaining_certs = ds.list_certificates(DirectoryId=directory_id)["CertificatesInfo"]
    assert remaining_certs == [], (
        f"RegisterCertificate was rejected but a certificate now appears in ListCertificates: {remaining_certs!r}"
    )


# ===== helpers =====
def _generate_self_signed_ca_pem() -> str | None:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sim2real-ds-test-ca")])
        now = datetime.datetime.utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=400))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    key_cert_sign=True,
                    crl_sign=True,
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    except ImportError:
        pass

    from fidelity_tests_runner import require_tools

    require_tools("openssl")
    with tempfile.TemporaryDirectory() as tmp:
        key_path = f"{tmp}/key.pem"
        cert_path = f"{tmp}/cert.pem"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-days", "400", "-nodes",
                "-subj", "/CN=sim2real-ds-test-ca",
                "-keyout", key_path, "-out", cert_path,
            ],
            check=True,
            capture_output=True,
        )
        with open(cert_path, "r", encoding="ascii") as fh:
            return fh.read()


def _best_effort(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DirectoryDoesNotExistException",
            "EntityDoesNotExistException",
        ):
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error_code_and_message(fn):
    try:
        fn()
    except ClientError as err:
        return (
            err.response["Error"]["Code"],
            err.response["Error"].get("Message"),
            err.response["ResponseMetadata"]["RequestId"],
        )
    raise AssertionError("expected the call to fail, but it succeeded")


def _ad_password() -> str:
    return "Sim2Real!" + secrets.token_hex(8) + "Aa1"


def _tag_spec(ctx, resource_type: str, kind: str):
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-ds-{kind}-")}],
    }


def _default_vpc_subnets(ec2, *, ctx):
    """Adopt the run's shared network when it has capacity, rather than always minting a
    dedicated one -- concurrent checks can otherwise exhaust the regional VPC quota, and
    CreateVpc fails with VpcLimitExceeded once that quota is exhausted."""
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        return None
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    subnets = sorted((s for s in subnets if s.get("AvailabilityZoneId") not in _DS_UNSUPPORTED_ZONE_IDS), key=lambda s: s["AvailabilityZone"])
    by_az: dict[str, str] = {}
    for s in subnets:
        if s["State"] == "available":
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        return None
    return vpc_id, list(by_az.values())[:2]


def _create_vpc_with_two_subnets(ctx):
    ec2 = ctx.client("ec2")

    default = _default_vpc_subnets(ec2, ctx=ctx)
    if default is not None:
        return default

    vpc_id = ec2.create_vpc(CidrBlock="10.176.0.0/16", TagSpecifications=[_tag_spec(ctx, "vpc", "vpc")])["Vpc"]["VpcId"]

    def _cleanup_vpc():
        try:
            _delete_net(ec2, "delete_vpc", VpcId=vpc_id)
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidVpcID.NotFound":
                raise

    ctx.on_cleanup(_cleanup_vpc)
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
    az_names = [az["ZoneName"] for az in azs[:2]]
    if len(az_names) < 2:
        raise AssertionError("region does not have 2 available AZs")

    subnet_ids = []
    for i, az in enumerate(az_names):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.176.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tag_spec(ctx, "subnet", "subnet")],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(subnet_id)

        def _cleanup_subnet(sid=subnet_id):
            try:
                _delete_net(ec2, "delete_subnet", SubnetId=sid)
            except ClientError as e:
                if e.response["Error"]["Code"] != "InvalidSubnetID.NotFound":
                    raise

        ctx.on_cleanup(_cleanup_subnet)
    return vpc_id, subnet_ids


def _create_active_microsoft_ad(ctx, ds, vpc_id, subnet_ids) -> str:
    name = f"{ctx.unique_name('sim2real-msad-')}.example.com"
    directory_id = ds.create_microsoft_ad(
        Name=name,
        Password=_ad_password(),
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
        Edition="Standard",
    )["DirectoryId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: _delete_directory_and_wait(ds, directory_id)))

    stage = _poll_until(
        lambda: ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]["Stage"],
        lambda s: s in ("Active", "Failed"),
        timeout_s=5400.0,
        interval_s=30.0,
    )
    if stage != "Active":
        raise AssertionError(f"directory reached terminal stage {stage!r} instead of Active")
    return directory_id


# Subnet / VPC deletes fail with DependencyViolation while a deleted directory's ENIs linger: wait
# (bounded) for the ENIs to go, retry DependencyViolation in one window shared by all of a check's
# network deletes, then raise naming the ENIs still attached.
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
        _time.sleep(2)
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
        _time.sleep(2)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]



def _delete_directory_and_wait(ds, directory_id, timeout_s=1140.0, interval_s=30.0):
    """Delete a directory and wait until it is gone, so its ENIs and security group leave the
    shared network. DeleteDirectory is retried while the directory is still being created or is
    still shared with another account."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ds.delete_directory(DirectoryId=directory_id)
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "EntityDoesNotExistException":
                return
            if "shared" in e.response["Error"].get("Message", "").lower():
                try:
                    shared = ds.describe_shared_directories(OwnerDirectoryId=directory_id)["SharedDirectories"]
                except ClientError as exc:
                    if exc.response["Error"]["Code"] not in (
                        "DirectoryDoesNotExistException",
                        "EntityDoesNotExistException",
                    ):
                        raise
                    shared = []
                for share in shared:
                    try:
                        ds.unshare_directory(
                            DirectoryId=directory_id,
                            UnshareTarget={"Id": share["SharedAccountId"], "Type": "ACCOUNT"},
                        )
                    except ClientError as exc:
                        if exc.response["Error"]["Code"] not in (
                            "DirectoryDoesNotExistException",
                            "EntityDoesNotExistException",
                        ):
                            raise
            elif code not in ("ClientException", "InvalidParameterException"):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
    while True:
        try:
            found = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "EntityDoesNotExistException":
                return
            raise
        if not found or found[0].get("Stage") == "Deleted":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"directory {directory_id} still exists {timeout_s:.0f}s after DeleteDirectory")
        time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
