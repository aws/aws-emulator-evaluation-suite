"""create-domain-name-access-association-without-vpce-fails."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-domain-name-access-association-without-vpce-fails"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating an access association referencing a non-existent VPC endpoint must
    fail BadRequestException rather than creating a dangling association, and this must
    hold against an account that is otherwise capable of creating a real one."""
    # One teardown deadline per run, shared by every teardown.
    td: list = []
    apigw = ctx.client("apigateway")

    domain = _create_private_domain(ctx, td)
    vpce = _create_execute_api_vpc_endpoint(ctx, td)

    # Positive control: a real, existing VPC endpoint must be accepted. Without this,
    # "rejects a non-existent VPC endpoint" is indistinguishable from "rejects every
    # access association", which is a materially weaker (and false) claim.
    created_assoc = apigw.create_domain_name_access_association(
        domainNameArn=domain["arn"],
        accessAssociationSourceType="VPCE",
        accessAssociationSource=vpce["vpce_id"],
    )
    assoc_arn = created_assoc["domainNameAccessAssociationArn"]
    ctx.on_cleanup(
        lambda: _ignore(
            td,
            lambda: apigw.delete_domain_name_access_association(domainNameAccessAssociationArn=assoc_arn),
            "NotFoundException",
        )
    )
    assert created_assoc["accessAssociationSource"] == vpce["vpce_id"], (
        f"positive control: expected the association's source to be {vpce['vpce_id']!r}, "
        f"got {created_assoc.get('accessAssociationSource')!r}"
    )

    positive_listed = apigw.get_domain_name_access_associations().get("items", [])
    assert any(a.get("domainNameAccessAssociationArn") == assoc_arn for a in positive_listed), (
        "positive control: an access association for a real VPC endpoint must be visible "
        "via an independent read (GetDomainNameAccessAssociations)"
    )

    bogus_vpce = "vpce-0123456789abcdef0"
    code, message = _error(
        lambda: apigw.create_domain_name_access_association(
            domainNameArn=domain["arn"],
            accessAssociationSourceType="VPCE",
            accessAssociationSource=bogus_vpce,
        )
    )
    assert code == "BadRequestException", (
        f"expected BadRequestException creating an access association for a "
        f"non-existent VPC endpoint, got {code!r}"
    )
    assert message == f"{bogus_vpce} is not a valid VPC endpoint id", f"unexpected BadRequestException message {message!r}"

    associations = apigw.get_domain_name_access_associations().get("items", [])
    assert not any(
        a["domainNameArn"] == domain["arn"] and a.get("accessAssociationSource") == bogus_vpce
        for a in associations
    ), "no access association must be created when the VPC endpoint does not exist"


_CLEANUP_S = 840.0
_TEARDOWN_RETRY_CODES = ("ConflictException", "ResourceInUseException")
_VPCE_GONE = ("InvalidVpcEndpointId.NotFound", "InvalidVpcEndpoint.NotFound")


def _teardown_deadline(td: list) -> float:
    """One deadline shared by all of the check's teardowns, started by the first one."""
    if not td:
        td.append(time.monotonic() + _CLEANUP_S)
    return td[0]


def _ignore(td, fn, *gone) -> None:
    """Teardown: done when fn succeeds or answers a `gone` code; retry in-use, conflict and
    update-in-progress refusals every 2 s to the teardown deadline, and raise everything else."""
    deadline = _teardown_deadline(td)
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            error = exc.response["Error"]
            if error["Code"] in gone:
                return
            in_progress = error["Code"] == "BadRequestException" and "update in progress" in error.get("Message", "")
            if not (error["Code"] in _TEARDOWN_RETRY_CODES or in_progress) or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _error(fn):
    """Call fn(); return (code, message) of the refusal. A call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _self_signed_cert_pem(common_name: str):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def _import_cert(ctx, common_name: str, td: list) -> str:
    cert_pem, key_pem = _self_signed_cert_pem(common_name)
    acm = ctx.client("acm")
    resp = acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem)
    cert_arn = resp["CertificateArn"]
    ctx.on_cleanup(
        lambda: _ignore(td, lambda: acm.delete_certificate(CertificateArn=cert_arn), "ResourceNotFoundException")
    )
    return cert_arn


def _create_domain_name_retrying(apigw, *, max_attempts: int = 6, **kwargs):
    """CreateDomainName is throttled account-wide on real AWS (TooManyRequestsException);
    retry with exponential backoff instead of failing on the first hit."""
    delay = 5.0
    for attempt in range(max_attempts):
        try:
            return apigw.create_domain_name(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "TooManyRequestsException" and attempt < max_attempts - 1:
                time.sleep(delay)
                delay = min(delay * 2, 60.0)
                continue
            raise


def _create_private_domain(ctx, td: list) -> dict:
    apigw = ctx.client("apigateway")
    domain_name = f"{ctx.unique_name('sim2real-priv-')}.internal.test".lower()
    cert_arn = _import_cert(ctx, domain_name, td)
    resp = _create_domain_name_retrying(
        apigw,
        domainName=domain_name,
        certificateArn=cert_arn,
        endpointConfiguration={"types": ["PRIVATE"]},
    )
    # A private domain name is addressed by its domainNameId; without it the delete targets a
    # public domain of the same name and answers NotFoundException.
    domain_name_id = resp["domainNameId"]
    ctx.on_cleanup(
        lambda: _ignore(
            td,
            lambda: apigw.delete_domain_name(domainName=domain_name, domainNameId=domain_name_id),
            "NotFoundException",
        )
    )
    return {"name": domain_name, "arn": resp["domainNameArn"]}


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            return result
        time.sleep(interval_s)
        result = probe()
    return result


def _create_execute_api_vpc_endpoint(ctx, td: list) -> dict:
    ec2 = ctx.client("ec2")
    tag = ctx.unique_name("sim2real-apigw-vpce-")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.221.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": tag}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _ignore(td, lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id), "InvalidVpcID.NotFound"))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.221.1.0/24",
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": tag}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(
        lambda: _ignore(td, lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id), "InvalidSubnetID.NotFound")
    )

    sg_id = ec2.create_security_group(
        GroupName=tag, Description="sim2real apigw vpc endpoint sg", VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": tag}]}],
    )["GroupId"]
    ctx.on_cleanup(
        lambda: _ignore(td, lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id), "InvalidGroup.NotFound")
    )

    vpce = ec2.create_vpc_endpoint(
        VpcId=vpc_id,
        ServiceName=f"com.amazonaws.{ctx.region}.execute-api",
        VpcEndpointType="Interface",
        SubnetIds=[subnet_id],
        SecurityGroupIds=[sg_id],
        PrivateDnsEnabled=False,
        TagSpecifications=[{"ResourceType": "vpc-endpoint", "Tags": [{"Key": "Name", "Value": tag}]}],
    )["VpcEndpoint"]
    vpce_id = vpce["VpcEndpointId"]

    def _cleanup_vpce():
        # DeleteVpcEndpoints reports per-endpoint failures in Unsuccessful, not as an error.
        failed = ec2.delete_vpc_endpoints(VpcEndpointIds=[vpce_id]).get("Unsuccessful", [])
        if any(f["Error"]["Code"] not in _VPCE_GONE for f in failed):
            raise RuntimeError(f"DeleteVpcEndpoints({vpce_id}) failed: {failed!r}")
        state = _poll_until(
            lambda: _vpce_state(ec2, vpce_id),
            lambda st: st in (None, "deleted"),
            timeout_s=max(1.0, _teardown_deadline(td) - time.monotonic()), interval_s=2,
        )
        if state not in (None, "deleted"):
            raise RuntimeError(f"VPC endpoint {vpce_id} still {state!r} at the teardown deadline")

    ctx.on_cleanup(_cleanup_vpce)

    state = _poll_until(
        lambda: ec2.describe_vpc_endpoints(VpcEndpointIds=[vpce_id])["VpcEndpoints"][0]["State"],
        lambda s: s in ("available", "failed"),
        timeout_s=300, interval_s=10,
    )
    if state != "available":
        raise AssertionError(f"VPC endpoint did not become available (state={state})")
    return {"vpc_id": vpc_id, "subnet_id": subnet_id, "sg_id": sg_id, "vpce_id": vpce_id}


def _vpce_state(ec2, vpce_id):
    """The endpoint's State, or None when DescribeVpcEndpoints does not know it."""
    try:
        items = ec2.describe_vpc_endpoints(VpcEndpointIds=[vpce_id]).get("VpcEndpoints", [])
    except ClientError as exc:
        if exc.response["Error"]["Code"] in _VPCE_GONE:
            return None
        raise
    return items[0]["State"] if items else None


# AWS-managed ENIs (endpoints, load balancers, functions) leave a VPC asynchronously after their
# owner's delete returns, so DeleteSubnet/DeleteSecurityGroup/DeleteVpc can fail with
# DependencyViolation. Wait (bounded) for the ENIs to go, retry inside the same window, and raise
# naming any ENIs still attached.
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
