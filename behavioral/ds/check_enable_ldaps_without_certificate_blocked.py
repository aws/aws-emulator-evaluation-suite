"""enable-ldaps-without-certificate-blocked."""
from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "enable-ldaps-without-certificate-blocked"
GROUP = "server-side"
SERVICES = ["ds"]

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

_DS_PASSWORD = "Sim2Real-Test-Pwd-1!"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """EnableLDAPS on a directory with no registered certificate fails with NoAvailableCertificateException
    and AWS's exact message and leaves LDAPS not Enabled; once a ClientLDAPS certificate is Registered,
    the same EnableLDAPS call reaches Enabled."""
    require_tools("openssl")
    _ds_slow_gate(ctx)

    ds = ctx.client("ds")
    vpc_id, subnet_ids = _create_vpc_for_directory(ctx)
    directory_id = _create_microsoft_ad(ctx, vpc_id, subnet_ids)
    _wait_for_stage(ctx, directory_id, {"Active"}, timeout_s=2700.0, interval_s=30.0)

    certs = ds.list_certificates(DirectoryId=directory_id)["CertificatesInfo"]
    assert certs == [], "a freshly created directory must have no registered certificates"

    code, message, request_id = _error(lambda: ds.enable_ldaps(DirectoryId=directory_id, Type="Client"))
    assert code == "NoAvailableCertificateException", (
        f"expected NoAvailableCertificateException enabling LDAPS with no registered certificate, got {code}"
    )
    assert message == (
        f"Cannot enable LDAPS since there is no valid certificate available. : RequestId: {request_id}"
    ), f"unexpected NoAvailableCertificateException message: {message!r}"

    settings = ds.describe_ldaps_settings(DirectoryId=directory_id)["LDAPSSettingsInfo"]
    assert all(s["LDAPSStatus"] != "Enabled" for s in settings), (
        f"LDAPS must not have been enabled without a certificate, got settings {settings}"
    )

    pem = _generate_self_signed_cert_pem("sim2real-ds-ldaps.test")
    cert_id = ds.register_certificate(
        DirectoryId=directory_id, CertificateData=pem, Type="ClientLDAPS"
    )["CertificateId"]
    # DeleteDirectory removes the registered certificate together with the directory.
    _wait_for_certificate_state(ctx, directory_id, cert_id, {"Registered"}, timeout_s=600.0)

    ds.enable_ldaps(DirectoryId=directory_id, Type="Client")
    final_status = _wait_for_ldaps_status(
        ctx, directory_id, {"Enabled", "EnableFailed"}, timeout_s=300.0, interval_s=10.0
    )
    assert final_status == "Enabled", (
        f"expected EnableLDAPS to reach the terminal status Enabled once a certificate is "
        f"registered, got {final_status}"
    )


def _ds_slow_gate(ctx) -> None:
    # Managed Microsoft AD takes ~20-45 minutes to provision and bills for its lifetime.
    return


def _error(fn):
    """(Error.Code, Error.Message, RequestId) of the refusal fn() must raise; a success raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message", ""), e.response["ResponseMetadata"]["RequestId"]
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


def _generate_self_signed_cert_pem(common_name: str) -> str:
    with tempfile.TemporaryDirectory() as tmp:
        key_path = str(Path(tmp) / "key.pem")
        cert_path = str(Path(tmp) / "cert.pem")
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", key_path, "-out", cert_path,
                "-days", "365", "-subj", f"/CN={common_name}",
            ],
            check=True,
            capture_output=True,
        )
        return Path(cert_path).read_text(encoding="ascii")


def _create_vpc_for_directory(ctx):
    ec2 = ctx.client("ec2")
    vpc = ec2.create_vpc(
        CidrBlock="10.190.0.0/16",
        TagSpecifications=[
            {
                "ResourceType": "vpc",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ds-vpc-")}],
            }
        ],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    azs = [
        az["ZoneName"]
        for az in ec2.describe_availability_zones(
            Filters=[{"Name": "zone-type", "Values": ["availability-zone"]}]
        )["AvailabilityZones"]
        if az["State"] == "available" and az.get("ZoneId") not in _DS_UNSUPPORTED_ZONE_IDS
    ][:2]
    if len(azs) < 2:
        raise AssertionError(f"region {ctx.region} does not expose 2 available AZs required for a DS directory VPC")

    subnet_ids = []
    for i, az in enumerate(azs):
        subnet = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.190.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[
                {
                    "ResourceType": "subnet",
                    "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ds-subnet-")}],
                }
            ],
        )["Subnet"]
        subnet_id = subnet["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)
    return vpc_id, subnet_ids


def _create_microsoft_ad(ctx, vpc_id, subnet_ids, edition: str = "Standard") -> str:
    ds = ctx.client("ds")
    name = f"{ctx.unique_name('sim2real-ds-')}.test"
    resp = ds.create_microsoft_ad(
        Name=name,
        Password=_DS_PASSWORD,
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
        Edition=edition,
    )
    directory_id = resp["DirectoryId"]
    ctx.on_cleanup(lambda: _delete_directory(ctx, directory_id))
    return directory_id


def _delete_directory(ctx, directory_id) -> None:
    """Delete the directory and wait until it is gone; with the network teardown it fits the
    1800 s cleanup budget. DeleteDirectory is retried while the directory is still being created."""
    ds = ctx.client("ds")
    deadline = time.monotonic() + 1140.0
    while True:
        try:
            ds.delete_directory(DirectoryId=directory_id)
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "EntityDoesNotExistException":
                return
            if code not in ("ClientException", "InvalidParameterException") or time.monotonic() >= deadline:
                raise
            time.sleep(2)
    _wait_for_stage(ctx, directory_id, {"Deleted"}, timeout_s=max(deadline - time.monotonic(), 0.0), interval_s=2.0)


def _wait_for_stage(ctx, directory_id, target_stages, timeout_s=2700.0, interval_s=30.0):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "EntityDoesNotExistException" and "Deleted" in target_stages:
                return "Deleted"
            raise
        if desc:
            stage = desc[0]["Stage"]
            if stage in target_stages:
                return stage
            if stage == "Failed":
                raise AssertionError(f"directory {directory_id} entered Failed stage while waiting for {target_stages}")
        elif "Deleted" in target_stages:
            return "Deleted"
        if time.monotonic() >= deadline:
            raise AssertionError(f"directory {directory_id} did not reach {target_stages} within {timeout_s}s")
        time.sleep(interval_s)


def _wait_for_certificate_state(ctx, directory_id, certificate_id, target_states, timeout_s=300.0, interval_s=10.0):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cert = ds.describe_certificate(DirectoryId=directory_id, CertificateId=certificate_id)["Certificate"]
        if cert["State"] in target_states:
            return cert["State"]
        if cert["State"] == "RegisterFailed":
            raise AssertionError(f"certificate {certificate_id} failed to register")
        time.sleep(interval_s)
    raise AssertionError(f"certificate {certificate_id} did not reach {target_states} within {timeout_s}s")


def _wait_for_ldaps_status(ctx, directory_id, target_statuses, timeout_s=300.0, interval_s=10.0):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        settings = ds.describe_ldaps_settings(DirectoryId=directory_id)["LDAPSSettingsInfo"]
        if settings and settings[0]["LDAPSStatus"] in target_statuses:
            return settings[0]["LDAPSStatus"]
        time.sleep(interval_s)
    raise AssertionError(f"LDAPS status for {directory_id} never reached {target_statuses} within {timeout_s}s")


# Asynchronously deleted resources (load balancers, directories, endpoints, ...) leave ENIs in the
# subnet / security group for a while, so an immediate delete fails with DependencyViolation. Wait
# (bounded) for the ENIs to go, retry DependencyViolation in the same window, then raise naming the
# ENIs still attached. The window is shared by all of one check's network deletes.
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
