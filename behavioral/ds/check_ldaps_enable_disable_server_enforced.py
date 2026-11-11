"""ldaps-enable-disable-server-enforced."""
from __future__ import annotations

import os
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

CHECK = "ldaps-enable-disable-server-enforced"
GROUP = "server-side"
SERVICES = ["ds"]

_PASSWORD = "Sim2Real-Ldaps-2024!"


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """With a registered self-signed certificate, EnableLDAPS drives DescribeLDAPSSettings'
    LDAPSStatus to Enabled, and DisableLDAPS then drives it to Disabled.

    Reference: https://docs.aws.amazon.com/directoryservice/latest/devguide/API_EnableLDAPS.html"""
    pem = _generate_self_signed_pem(ctx)

    ds = ctx.client("ds")
    # One teardown deadline per run, shared by every teardown below.
    teardown: dict = {}
    vpc_id, subnet_ids = _create_vpc_with_subnets(ctx, teardown)

    name = f"{ctx.unique_name('sim2real-ds-ldaps').rstrip('-').lower()}.example.com"
    directory_id = ds.create_microsoft_ad(
        Name=name,
        Password=_PASSWORD,
        Edition="Standard",
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
        Tags=[{"Key": "Name", "Value": name}],
    )["DirectoryId"]
    ctx.on_cleanup(lambda: _delete_directory_and_wait(ds, directory_id, teardown))

    _wait_directory_active(ds, directory_id, timeout_s=2700.0)

    baseline = ds.describe_ldaps_settings(DirectoryId=directory_id, Type="Client")["LDAPSSettingsInfo"]
    assert not any(s["LDAPSStatus"] == "Enabled" for s in baseline), (
        f"a freshly created directory must not already report Client LDAPS Enabled, got {baseline}"
    )

    certificate_id = ds.register_certificate(
        DirectoryId=directory_id, CertificateData=pem, Type="ClientLDAPS"
    )["CertificateId"]
    ctx.on_cleanup(lambda: _deregister_certificate_best_effort(ds, directory_id, certificate_id))
    cert_state = _wait_certificate_terminal(ds, directory_id, certificate_id, timeout_s=600.0)
    assert cert_state == "Registered", f"expected certificate to register, got {cert_state}"

    # The admin guide says standalone-CA certificates are unsupported, but AWS does not block
    # EnableLDAPS with a self-signed one: it goes Enabling -> Enabled, not EnableFailed.
    ds.enable_ldaps(DirectoryId=directory_id, Type="Client")
    status = _wait_ldaps_terminal(ds, directory_id, timeout_s=1800.0)
    assert status == "Enabled", (
        f"expected a freshly registered self-signed certificate to reach Enabled "
        f"(measured real-AWS behavior), got {status}"
    )

    ds.disable_ldaps(DirectoryId=directory_id, Type="Client")
    status_after_disable = _wait_ldaps_status(ds, directory_id, {"Disabled"}, timeout_s=900.0)
    assert status_after_disable == "Disabled", (
        f"expected DisableLDAPS to drive LDAPSStatus to Disabled, got {status_after_disable}"
    )


def _generate_self_signed_pem(ctx) -> str:
    try:
        return _generate_self_signed_pem_cryptography()
    except ImportError:
        pass
    require_tools("openssl")
    return _generate_self_signed_pem_openssl(ctx)


def _generate_self_signed_pem_cryptography() -> str:
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sim2real-ldaps-test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=400))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _generate_self_signed_pem_openssl(ctx) -> str:
    import subprocess
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        key_path = os.path.join(tmp, "key.pem")
        cert_path = os.path.join(tmp, "cert.pem")
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key_path,
                "-out", cert_path, "-days", "400", "-nodes", "-subj", "/CN=sim2real-ldaps-test",
            ],
            check=True,
            capture_output=True,
            env=ctx.subprocess_env(),
        )
        with open(cert_path, "r") as fh:
            return fh.read()


def _create_vpc_with_subnets(ctx, teardown: dict, cidr_prefix: str = "10.94"):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock=f"{cidr_prefix}.0.0/16",
        TagSpecifications=[
            {
                "ResourceType": "vpc",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ds-vpc-")}],
            }
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, teardown, "delete_vpc", VpcId=vpc_id))

    azs = [a["ZoneName"] for a in ec2.describe_availability_zones()["AvailabilityZones"]][:2]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"{cidr_prefix}.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[
                {
                    "ResourceType": "subnet",
                    "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ds-subnet-")}],
                }
            ],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, teardown, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)
    return vpc_id, subnet_ids


def _wait_directory_active(ds, directory_id, timeout_s=2700.0, interval_s=30.0):
    deadline = time.monotonic() + timeout_s
    stage = None
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
        stage = desc["Stage"]
        if stage == "Active":
            return desc
        if stage == "Failed":
            raise AssertionError(f"directory {directory_id} entered Failed stage")
        time.sleep(interval_s)
    raise AssertionError(f"directory {directory_id} did not reach Active (last stage={stage})")


def _wait_certificate_terminal(ds, directory_id, certificate_id, timeout_s=600.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = ds.describe_certificate(DirectoryId=directory_id, CertificateId=certificate_id)["Certificate"]["State"]
        if state in ("Registered", "RegisterFailed"):
            return state
        time.sleep(interval_s)
    raise AssertionError(f"certificate {certificate_id} did not reach a terminal state (last={state})")


def _wait_ldaps_terminal(ds, directory_id, timeout_s=1800.0, interval_s=20.0):
    return _wait_ldaps_status(ds, directory_id, {"Enabled", "EnableFailed"}, timeout_s=timeout_s, interval_s=interval_s)


def _wait_ldaps_status(ds, directory_id, terminal_statuses, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        settings = ds.describe_ldaps_settings(DirectoryId=directory_id, Type="Client")["LDAPSSettingsInfo"]
        status = settings[0]["LDAPSStatus"] if settings else None
        if status in terminal_statuses:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"LDAPS status did not reach {terminal_statuses} within {timeout_s}s (last={status})")


def _deregister_certificate_best_effort(ds, directory_id, certificate_id):
    from botocore.exceptions import ClientError

    try:
        ds.deregister_certificate(DirectoryId=directory_id, CertificateId=certificate_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "CertificateDoesNotExistException",
            "DirectoryDoesNotExistException",
        ):
            raise


#: The suite's 1800 s cleanup budget, less a margin: every teardown of the run shares this one
#: deadline, started by the first teardown that asks for it.
_TEARDOWN_BUDGET_S = 1740.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_GONE = ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound")


def _teardown_deadline(teardown: dict) -> float:
    return teardown.setdefault("t", time.monotonic() + _TEARDOWN_BUDGET_S)


def _delete_directory_and_wait(ds, directory_id, teardown: dict) -> None:
    """Delete the directory and poll every 2 s until it is gone: EntityDoesNotExistException or
    Stage Deleted (a deleted directory keeps describing). A ClientException while the directory
    is still being created is retried; anything else, or the run's teardown deadline, raises."""
    deadline = _teardown_deadline(teardown)
    while True:
        try:
            ds.delete_directory(DirectoryId=directory_id)
            break
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "EntityDoesNotExistException":
                return
            stage = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]["Stage"]
            busy = code == "ClientException" and stage in ("Requested", "Creating", "Created")
            if not busy or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    stage = None
    while True:
        try:
            found = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "EntityDoesNotExistException":
                return
            raise
        stage = found[0]["Stage"] if found else "Deleted"
        if stage == "Deleted":
            return
        if time.monotonic() >= deadline:
            raise RuntimeError(f"directory {directory_id} is still {stage} at the teardown deadline")
        time.sleep(2)


def _delete_net(client, teardown: dict, op, **ident):
    """Run an EC2 network delete: a not-found answer is done; DependencyViolation (the directory's
    ENIs leave the subnets after it is deleted) is retried every 2 s to the run's teardown deadline,
    then raised naming the ENIs still attached."""
    deadline = _teardown_deadline(teardown)
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while True:
        try:
            return getattr(client, op)(**ident)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in _NET_GONE:
                return None
            if code != "DependencyViolation":
                raise
            if time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation at the teardown deadline; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        time.sleep(2)


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
