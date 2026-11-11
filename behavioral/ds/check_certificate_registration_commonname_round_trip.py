"""certificate-registration-commonname-round-trip."""
from __future__ import annotations

import datetime
import time
from itertools import combinations

from behavioral_harness import tags
from botocore.exceptions import ClientError

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "certificate-registration-commonname-round-trip"
GROUP = "representation"
SERVICES = ["ds"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterCertificate's PEM is parsed correctly: DescribeCertificate reports the same CommonName."""
    common_name = ctx.unique_name("sim2real-ds-cert-")
    pem = _generate_self_signed_ca_pem(common_name)

    vpc_id, az_to_subnet = _get_or_create_vpc_with_subnets(ctx)
    ds = ctx.client("ds")
    directory_id = _create_microsoft_ad_with_working_azs(
        ds, _domain_name(ctx, "cert"), _ds_password(), vpc_id, az_to_subnet
    )
    ctx.on_cleanup(lambda: _delete_directory_when_ready(ctx, directory_id, timeout_s=1140))

    # AWS Managed Microsoft AD directories can take up to ~45 minutes to reach
    # Active; see https://docs.aws.amazon.com/directoryservice/latest/admin-guide/directory_microsoft_ad.html
    _wait_for_directory_stage(ctx, directory_id, {"Active"}, timeout_s=3600, interval_s=30)

    cert_id = ds.register_certificate(
        DirectoryId=directory_id, CertificateData=pem, Type="ClientLDAPS"
    )["CertificateId"]
    deregistered = {"done": False}

    def _cleanup_cert():
        if deregistered["done"]:
            return
        try:
            ds.deregister_certificate(DirectoryId=directory_id, CertificateId=cert_id)
        except ClientError as e:
            if e.response["Error"]["Code"] != "CertificateDoesNotExistException":
                raise

    ctx.on_cleanup(_cleanup_cert)

    # A ClientLDAPS certificate can stay "Registering" past 300 s (LDAPS registration validates
    # against the directory's domain controllers), so this polls up to 900 s.
    cert = _wait_for_certificate_state(
        ctx, directory_id, cert_id, {"Registered", "RegisterFailed"}, timeout_s=900
    )
    assert cert["State"] == "Registered", (
        f"certificate registration ended in state {cert['State']!r}: {cert.get('StateReason')!r}"
    )
    assert cert["CommonName"] == common_name, (
        f"CommonName not parsed correctly from the registered PEM: "
        f"{cert['CommonName']!r} != {common_name!r}"
    )
    assert cert["Type"] == "ClientLDAPS", f"Type not preserved: {cert['Type']!r} != 'ClientLDAPS'"

    ds.deregister_certificate(DirectoryId=directory_id, CertificateId=cert_id)
    deregistered["done"] = True
    # DescribeCertificate can keep answering for minutes after DeregisterCertificate returns for a
    # ClientLDAPS certificate, so this polls up to 900 s for CertificateDoesNotExistException.
    err = _poll_for_client_error(
        lambda: ds.describe_certificate(DirectoryId=directory_id, CertificateId=cert_id),
        timeout_s=900,
    )
    code = err.response["Error"]["Code"] if err is not None else None
    assert code == "CertificateDoesNotExistException", (
        f"expected CertificateDoesNotExistException from DescribeCertificate after "
        f"DeregisterCertificate, got {code!r}"
    )
    expected_message = (
        f"Certificate {cert_id} does not exist for directoryId: {directory_id} "
        f": RequestId: {err.response['ResponseMetadata']['RequestId']}"
    )
    message = err.response["Error"].get("Message")
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"


# ===== helpers =====
def _ds_password() -> str:
    return "Sim2Real-Test1234!"


def _domain_name(ctx, kind: str) -> str:
    base = ctx.unique_name(f"sim2real-ds-{kind}-")
    return f"{base}.test"


def _get_or_create_vpc_with_subnets(ctx):
    """Adopt an existing VPC with subnets in >=2 AZs if one is available; otherwise create a
    dedicated one with a subnet in every AZ the region reports available. A freshly provisioned
    account may have no shared network at all, so this cannot assume one exists. Returns
    (vpc_id, {az: subnet_id}) rather than a fixed pair of 2, because Directory Service does not
    accept every AZ a region reports (see _create_microsoft_ad_with_working_azs)."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    for vpc in vpcs:
        subnets = ec2.describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [vpc["VpcId"]]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
        ).get("Subnets", [])
        subnets = sorted((s for s in subnets if s.get("AvailabilityZoneId") not in _DS_UNSUPPORTED_ZONE_IDS), key=lambda s: s["AvailabilityZone"])
        by_az: dict[str, str] = {}
        for s in subnets:
            if s["State"] == "available":
                by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        if len(by_az) >= 2:
            return vpc["VpcId"], by_az

    name = ctx.unique_name("sim2real-ds-cert-net-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.91.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    azs = [
        az["ZoneName"]
        for az in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    ]
    if len(azs) < 2:
        raise AssertionError("region does not expose at least 2 available AZs for directory subnets")

    by_az: dict[str, str] = {}
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.91.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[
                {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": f"{name}-{i}"}]}
            ],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        ec2.get_waiter("subnet_available").wait(SubnetIds=[subnet_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
        by_az[az] = subnet_id
    return vpc_id, by_az


def _create_microsoft_ad_with_working_azs(ds, name, password, vpc_id, az_to_subnet):
    """Directory Service rejects some AZs a region otherwise reports available -- observed on
    real AWS as a synchronous ClientException ("Failed to locate Availability Zone ... This
    availability zone may be capacity constrained") naming the offending subnet -- so this tries
    successive AZ pairs instead of assuming the first two returned by EC2 are acceptable."""
    azs = sorted(az_to_subnet)
    if len(azs) < 2:
        raise AssertionError(f"need >=2 AZs with an available subnet, have {azs}")
    last_error = None
    for az_a, az_b in combinations(azs, 2):
        try:
            return ds.create_microsoft_ad(
                Name=name,
                Password=password,
                Edition="Standard",
                VpcSettings={
                    "VpcId": vpc_id,
                    "SubnetIds": [az_to_subnet[az_a], az_to_subnet[az_b]],
                },
            )["DirectoryId"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "ClientException" and "Availability Zone" in str(e):
                last_error = e
                continue
            raise
    raise AssertionError(
        f"CreateMicrosoftAD rejected every pair of the available AZs {azs}: {last_error}"
    )


def _poll_for_client_error(fn, *, timeout_s: float, interval_s: float = 10.0):
    """The ClientError fn() first raises within timeout_s, or None if it kept succeeding."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            fn()
        except ClientError as e:
            return e
        time.sleep(interval_s)
    return None


def _wait_for_directory_stage(ctx, directory_id, target_stages, timeout_s, interval_s=20):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    stage = None
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
        stage = desc["Stage"]
        if stage in target_stages:
            return desc
        time.sleep(interval_s)
    raise AssertionError(
        f"directory {directory_id} did not reach {target_stages} within {timeout_s}s (last stage={stage})"
    )


def _delete_directory_when_ready(ctx, directory_id, timeout_s=1140):
    # Bounded so this wait and the 630 s network teardown fit the 1800 s cleanup budget; the
    # delete then reports any refusal itself.
    ds = ctx.client("ds")
    try:
        _wait_for_directory_stage(ctx, directory_id, {"Active", "Failed", "Impaired", "Inoperable"}, timeout_s)
    except AssertionError:
        pass
    try:
        ds.delete_directory(DirectoryId=directory_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "EntityDoesNotExistException":
            raise


def _wait_for_certificate_state(ctx, directory_id, certificate_id, target_states, timeout_s, interval_s=10):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    cert = None
    while time.monotonic() < deadline:
        cert = ds.describe_certificate(DirectoryId=directory_id, CertificateId=certificate_id)["Certificate"]
        if cert["State"] in target_states:
            return cert
        time.sleep(interval_s)
    raise AssertionError(
        f"certificate {certificate_id} did not reach {target_states} within {timeout_s}s (last={cert!r})"
    )


def _generate_self_signed_ca_pem(common_name: str):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.utcnow()
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=730))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
