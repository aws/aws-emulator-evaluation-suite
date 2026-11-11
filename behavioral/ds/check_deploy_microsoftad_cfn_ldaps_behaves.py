"""deploy-microsoftad-cfn-ldaps-behaves."""
from __future__ import annotations

import json
import re
import subprocess
import tempfile
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "deploy-microsoftad-cfn-ldaps-behaves"
GROUP = "deploy"
SERVICES = ["ds"]

_PASSWORD = "Sim2Real-Ds-Pw9!"
_DIR_ACTIVE_TIMEOUT_S = 3600.0
_STACK_TIMEOUT_S = 3600.0
_CERT_TIMEOUT_S = 600.0
_LDAPS_TIMEOUT_S = 1800.0


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CFN-deployed MicrosoftAD directory supports enabling client LDAPS after deploy,
    and DescribeLDAPSSettings reports LDAPSStatus Enabled."""
    require_tools("openssl")

    ds = ctx.client("ds")
    vpc = _create_vpc_with_subnets(ctx)
    domain = ctx.unique_name("sim2real-ds-msad-").lower() + ".test"

    stack = _deploy_cfn_stack_with_az_retry(ctx, vpc, domain, timeout_s=_budget_s(ctx, _STACK_TIMEOUT_S))
    directory_id = stack["outputs"]["DirectoryId"]

    desc = _wait_for_directory_stage(
        ctx, ds, directory_id, target_stages={"Active"}, timeout_s=_budget_s(ctx, _DIR_ACTIVE_TIMEOUT_S)
    )
    assert desc["Stage"] == "Active", f"expected directory {directory_id} stage Active, got {desc['Stage']!r}"

    cert_pem = _generate_self_signed_pem(ctx)
    cert_id = ds.register_certificate(
        DirectoryId=directory_id, CertificateData=cert_pem, Type="ClientLDAPS"
    )["CertificateId"]
    ctx.on_cleanup(lambda: _deregister_certificate_after_ldaps(ds, directory_id, cert_id))
    _wait_for_certificate_registered(ctx, ds, directory_id, cert_id, timeout_s=_budget_s(ctx, _CERT_TIMEOUT_S))

    ds.enable_ldaps(DirectoryId=directory_id, Type="Client")
    settings = _wait_for_ldaps_status(
        ctx, ds, directory_id, target_statuses={"Enabled"}, timeout_s=_budget_s(ctx, _LDAPS_TIMEOUT_S)
    )
    # LDAPSSettingInfo has no Type field, so the requested Type="Client" is not re-observable.
    assert settings["LDAPSStatus"] == "Enabled", f"expected LDAPSStatus Enabled, got {settings['LDAPSStatus']!r}"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _create_vpc_with_subnets(ctx) -> dict:
    ec2 = ctx.client("ec2")

    # Reuse the shared VPC when it has subnets in 2+ AZs: a fresh VPC per run hits VpcLimitExceeded.
    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get(
        "Vpcs", []
    )
    if default_vpcs:
        vpc_id = default_vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get(
            "Subnets", []
        )
        subnets = sorted((s for s in subnets if s.get("AvailabilityZoneId") not in _DS_UNSUPPORTED_ZONE_IDS), key=lambda s: s["AvailabilityZone"])
        by_az: dict[str, str] = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        if len(by_az) >= 2:
            # Keep every distinct-AZ subnet: Directory Service can reject a capacity-constrained
            # AZ, so the deploy retry needs alternatives.
            return {"vpc_id": vpc_id, "subnet_ids": list(by_az.values())}

    name = ctx.unique_name("sim2real-ds-vpc-")
    vpc_id = ec2.create_vpc(CidrBlock="10.89.0.0/16", TagSpecifications=[_tag_spec("vpc", name)])[
        "Vpc"
    ]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    from botocore.exceptions import WaiterError

    try:
        ec2.get_waiter("vpc_available").wait(
            VpcIds=[vpc_id],
            WaiterConfig={"Delay": 1, "MaxAttempts": max(1, int(_budget_s(ctx, 600.0)))},
        )
    except WaiterError:
        if _budget_spent(ctx):
            raise TimeoutError(f"vpc {vpc_id} available: the run budget ended first; not graded") from None
        raise

    azs = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"]]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.89.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tag_spec("subnet", f"{name}-{i}")],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: ec2.delete_subnet(SubnetId=sid))
        subnet_ids.append(subnet_id)
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids}


def _wait_for_directory_stage(ctx, ds, directory_id, target_stages, timeout_s, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    stage = None
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
        stage = desc["Stage"]
        if stage in target_stages:
            return desc
        if stage in ("Failed", "Inoperable"):
            raise AssertionError(f"directory {directory_id} entered terminal stage {stage}")
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"directory {directory_id} reaching {target_stages}: the run budget ended first; not graded")
    raise AssertionError(
        f"directory {directory_id} did not reach {target_stages} within {timeout_s}s "
        f"(last stage={stage})"
    )


def _deploy_cfn_stack(ctx, template_body, timeout_s=3600.0):
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-ds-stack-")
    cfn.create_stack(StackName=stack_name, TemplateBody=template_body)
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        status = stacks[0]["StackStatus"]
        if status == "CREATE_COMPLETE":
            outputs = {o["OutputKey"]: o["OutputValue"] for o in stacks[0].get("Outputs", [])}
            return {"stack_name": stack_name, "outputs": outputs}
        if status.endswith("FAILED") or status == "ROLLBACK_COMPLETE":
            reasons = [
                f"{e['LogicalResourceId']}: {e.get('ResourceStatusReason', '(no reason)')}"
                for e in cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
                if e["ResourceStatus"].endswith("FAILED")
            ]
            raise AssertionError(f"stack {stack_name} entered {status}: {reasons}")
        time.sleep(2.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"stack {stack_name} CREATE_COMPLETE: the run budget ended first; not graded")
    raise AssertionError(
        f"stack {stack_name} did not reach CREATE_COMPLETE within {timeout_s}s (last={status})"
    )


_BAD_AZ_SUBNET_RE = re.compile(r"corresponding to subnet: (subnet-[0-9a-f]+)")


def _deploy_cfn_stack_with_az_retry(ctx, vpc, domain, timeout_s):
    candidates = list(vpc["subnet_ids"])
    attempts = 0
    last_error: AssertionError | None = None
    while len(candidates) >= 2:
        attempts += 1
        pair = candidates[:2]
        template_body = json.dumps(
            {
                "Resources": {
                    "Directory": {
                        "Type": "AWS::DirectoryService::MicrosoftAD",
                        "Properties": {
                            "Name": domain,
                            "Password": _PASSWORD,
                            "Edition": "Standard",
                            "VpcSettings": {"VpcId": vpc["vpc_id"], "SubnetIds": pair},
                        },
                    }
                },
                "Outputs": {"DirectoryId": {"Value": {"Ref": "Directory"}}},
            }
        )
        try:
            return _deploy_cfn_stack(ctx, template_body, timeout_s=timeout_s)
        except AssertionError as err:
            # Directory Service can reject a "capacity constrained" AZ; the error names the
            # offending subnet, so drop only that one and retry with the next pair.
            match = _BAD_AZ_SUBNET_RE.search(str(err))
            bad_subnet = match.group(1) if match else None
            if bad_subnet is None or bad_subnet not in candidates:
                raise
            last_error = err
            candidates = [s for s in candidates if s != bad_subnet]
    raise AssertionError(
        f"exhausted AZ-pair retries after {attempts} attempt(s); last error: {last_error}"
    )


def _generate_self_signed_pem(ctx) -> str:
    env = ctx.subprocess_env()
    with tempfile.TemporaryDirectory() as tmp:
        key_path = f"{tmp}/key.pem"
        cert_path = f"{tmp}/cert.pem"
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-days",
                "365",
                "-nodes",
                "-subj",
                "/CN=sim2real-ds-ldaps-test",
                "-keyout",
                key_path,
                "-out",
                cert_path,
            ],
            check=True,
            capture_output=True,
            env=env,
        )
        # RegisterCertificate's CertificateData is a modeled String, not a Blob -- botocore's
        # ParamValidationError rejects bytes here even though PEM is ASCII-safe.
        with open(cert_path, "r") as fh:
            return fh.read()


def _wait_for_certificate_registered(ctx, ds, directory_id, cert_id, timeout_s, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = ds.describe_certificate(DirectoryId=directory_id, CertificateId=cert_id)[
            "Certificate"
        ]["State"]
        if state == "Registered":
            return
        if state == "RegisterFailed":
            raise AssertionError(f"certificate {cert_id} entered RegisterFailed")
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"certificate {cert_id} Registered: the run budget ended first; not graded")
    raise AssertionError(f"certificate {cert_id} did not become Registered (last={state})")


def _wait_for_ldaps_status(ctx, ds, directory_id, target_statuses, timeout_s, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    info = None
    while time.monotonic() < deadline:
        entries = ds.describe_ldaps_settings(DirectoryId=directory_id)["LDAPSSettingsInfo"]
        if entries:
            info = entries[0]
            if info["LDAPSStatus"] in target_statuses:
                return info
            if info["LDAPSStatus"] == "EnableFailed":
                raise AssertionError(f"LDAPS entered EnableFailed: {info}")
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"LDAPS reaching {target_statuses}: the run budget ended first; not graded")
    raise AssertionError(f"LDAPS did not reach {target_statuses} within {timeout_s}s (last={info})")


def _deregister_certificate_after_ldaps(ds, directory_id, cert_id):
    """DeregisterCertificate is refused while client LDAPS is enabled, so disable it first."""
    from botocore.exceptions import ClientError

    try:
        ds.disable_ldaps(DirectoryId=directory_id, Type="Client")
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("InvalidLDAPSStatusException", "EntityDoesNotExistException"):
            raise
    deadline = time.monotonic() + 600.0
    while True:
        try:
            ds.deregister_certificate(DirectoryId=directory_id, CertificateId=cert_id)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("CertificateDoesNotExistException", "EntityDoesNotExistException"):
                return
            if code != "UnsupportedOperationException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
