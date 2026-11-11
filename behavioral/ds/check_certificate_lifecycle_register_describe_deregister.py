"""certificate-lifecycle-register-describe-deregister."""
from __future__ import annotations

import datetime
import subprocess
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "certificate-lifecycle-register-describe-deregister"
GROUP = "state-machine"
SERVICES = ["ds"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterCertificate on an Active directory accepts a self-signed ClientLDAPS PEM that settles
    in Registered, and DeregisterCertificate removes it so DescribeCertificate and a second
    DeregisterCertificate answer CertificateDoesNotExistException."""
    pem = _generate_self_signed_cert_pem(f"{ctx.unique_name('sim2realcert')}.invalid")

    ds = ctx.client("ds")
    directory_id = _create_microsoft_ad(ctx)
    ctx.on_cleanup(lambda: _cleanup_delete_directory(ctx, directory_id))
    desc = _wait_for_directory_stage(ctx, ds, directory_id, {"Active", "Failed"}, timeout_s=5400)
    assert desc["Stage"] == "Active", f"directory reached stage {desc['Stage']!r} instead of Active"

    certificate_id = ds.register_certificate(
        DirectoryId=directory_id, CertificateData=pem, Type="ClientLDAPS"
    )["CertificateId"]

    def _cleanup_cert():
        try:
            ds.deregister_certificate(DirectoryId=directory_id, CertificateId=certificate_id)
        except ClientError as e:
            if e.response["Error"]["Code"] != "CertificateDoesNotExistException":
                raise

    ctx.on_cleanup(_cleanup_cert)

    cert = _wait_for_certificate_state(ctx, ds, directory_id, certificate_id, {"Registered", "RegisterFailed"}, timeout_s=600)
    assert cert["State"] == "Registered", f"certificate reached {cert['State']!r} instead of Registered"

    ds.deregister_certificate(DirectoryId=directory_id, CertificateId=certificate_id)
    err = _client_error(
        lambda: ds.describe_certificate(DirectoryId=directory_id, CertificateId=certificate_id), timeout_s=780
    )
    code = err.response["Error"]["Code"]
    assert code == "CertificateDoesNotExistException", f"expected 404 after deregister, got code={code!r}"
    expected_message = (
        f"Certificate {certificate_id} does not exist for directoryId: {directory_id} "
        f": RequestId: {err.response['ResponseMetadata']['RequestId']}"
    )
    message = err.response["Error"].get("Message")
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    rederegister_err = _client_error(
        lambda: ds.deregister_certificate(DirectoryId=directory_id, CertificateId=certificate_id)
    )
    rederegister_code = rederegister_err.response["Error"]["Code"]
    assert rederegister_code == "CertificateDoesNotExistException", (
        f"deregistering an already-deregistered certificate should still 404, "
        f"got code={rederegister_code!r}"
    )
    expected_message = (
        f"Certificate {certificate_id} does not exist for directoryId: {directory_id} "
        f": RequestId: {rederegister_err.response['ResponseMetadata']['RequestId']}"
    )
    message = rederegister_err.response["Error"].get("Message")
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"


# ===== helpers =====

def _client_error(fn, timeout_s=0.0):
    """Call fn() every 2 s until it raises and return the ClientError; a success past timeout_s raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as e:
            return e
        if time.monotonic() >= deadline:
            raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")
        time.sleep(2)


def _generate_self_signed_cert_pem(cn: str) -> str:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        now = datetime.datetime.utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
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
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", key_path, "-out", cert_path, "-days", "365",
                "-subj", f"/CN={cn}",
            ],
            check=True,
            capture_output=True,
        )
        with open(cert_path) as f:
            return f.read()


def _tag_spec(ctx, resource_type: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-ds-{resource_type}-")}],
    }


def _create_vpc_with_subnets(ctx):
    # No dependence on the ambient default VPC: create the network this check needs, rather
    # than inheriting whatever AZ layout the account happens to have (see the CreateMicrosoftAD
    # retry below for why a fixed AZ pair is not safe either).
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.178.0.0/16", TagSpecifications=[_tag_spec(ctx, "vpc")])["Vpc"]["VpcId"]

    def _cleanup_vpc():
        try:
            _delete_net(ec2, "delete_vpc", VpcId=vpc_id)
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidVpcID.NotFound":
                raise

    ctx.on_cleanup(_cleanup_vpc)
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    azs = [
        az["ZoneName"]
        for az in ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
            "AvailabilityZones"
        ]
    ]
    if len(azs) < 2:
        raise AssertionError(f"region has only {len(azs)} available AZ(s); CreateMicrosoftAD needs >=2")

    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.178.{i}.0/24", AvailabilityZone=az,
            TagSpecifications=[_tag_spec(ctx, "subnet")],
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


def _create_microsoft_ad(ctx) -> str:
    # Simple AD (ds.create_directory / Size=) is withdrawn: real AWS rejects it with
    # "Simple AD is no longer open to new customers" (ClientException). AWS Managed
    # Microsoft AD is the live equivalent for an Active directory prerequisite.
    ds = ctx.client("ds")
    vpc_id, subnet_ids = _create_vpc_with_subnets(ctx)
    name = f"{ctx.unique_name('sim2realds')}.test"

    # Real AWS can reject a specific AZ for directory placement as capacity-constrained
    # ("Failed to locate Availability Zone ... corresponding to subnet ... This availability
    # zone may be capacity constrained."), independent of which VPC owns the subnet. Retry
    # across consecutive AZ pairs rather than assuming any given pair is viable.
    remaining = list(subnet_ids)
    last_error: ClientError | None = None
    while len(remaining) >= 2:
        pair = remaining[:2]
        try:
            resp = ds.create_microsoft_ad(
                Name=name,
                Password="Sim2Real-Test-Passw0rd!",
                VpcSettings={"VpcId": vpc_id, "SubnetIds": pair},
                Edition="Standard",
            )
            return resp["DirectoryId"]
        except ClientError as e:
            code = e.response["Error"]["Code"]
            message = e.response["Error"]["Message"]
            if code != "ClientException" or "Availability Zone" not in message:
                raise
            last_error = e
            remaining = remaining[1:]
    raise AssertionError(f"no viable AZ pair among {subnet_ids} for CreateMicrosoftAD: {last_error}")


def _cleanup_delete_directory(ctx, directory_id: str) -> None:
    ds = ctx.client("ds")
    try:
        ds.delete_directory(DirectoryId=directory_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "EntityDoesNotExistException":
            raise


def _wait_for_directory_stage(ctx, ds, directory_id: str, targets: set[str], timeout_s: float = 2700.0, interval_s: float = 30.0):
    deadline = time.monotonic() + timeout_s
    last_stage = None
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
        last_stage = desc["Stage"]
        if last_stage in targets:
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"directory {directory_id} stuck at stage {last_stage!r} after {timeout_s}s")


def _wait_for_certificate_state(ctx, ds, directory_id: str, certificate_id: str, targets: set[str], timeout_s: float = 600.0, interval_s: float = 10.0):
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        cert = ds.describe_certificate(DirectoryId=directory_id, CertificateId=certificate_id)["Certificate"]
        last_state = cert["State"]
        if last_state in targets:
            return cert
        time.sleep(interval_s)
    raise AssertionError(f"certificate {certificate_id} stuck at state {last_state!r} after {timeout_s}s")


# Subnet / VPC deletes fail with DependencyViolation while a deleted directory's ENIs linger: wait
# (bounded) for the ENIs to go, retry DependencyViolation in one window shared by all of a check's
# network deletes, then raise naming the ENIs still attached.
_NET_TEARDOWN_S = 1500.0  # the directory delete does not wait, so the network window takes the budget
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
