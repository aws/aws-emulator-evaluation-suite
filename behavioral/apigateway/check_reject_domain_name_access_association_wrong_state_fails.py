"""reject-domain-name-access-association-wrong-state-fails."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reject-domain-name-access-association-wrong-state-fails"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Reject on a same-account access association fails with BadRequestException and leaves it
    intact, since Reject only applies to associations shared from another account; Delete still
    removes it."""
    apigw = ctx.client("apigateway")

    domain = _create_private_domain(ctx)
    vpce_id = _create_execute_api_vpce(ctx)

    assoc = apigw.create_domain_name_access_association(
        domainNameArn=domain["arn"],
        accessAssociationSourceType="VPCE",
        accessAssociationSource=vpce_id,
    )
    assoc_arn = assoc["domainNameAccessAssociationArn"]
    ctx.on_cleanup(
        lambda: _safe(
            lambda: apigw.delete_domain_name_access_association(
                domainNameAccessAssociationArn=assoc_arn
            ),
            "NotFoundException",
        )
    )

    code, message = _error(
        lambda: apigw.reject_domain_name_access_association(
            domainNameAccessAssociationArn=assoc_arn,
            domainNameArn=domain["arn"],
        )
    )
    assert code == "BadRequestException", (
        f"expected BadRequestException rejecting a same-account access association "
        f"(reject only applies to an association shared from a different AWS account), "
        f"got {code!r}"
    )
    assert message == (
        "Cannot reject the domain name access association when the private custom domain and "
        "domain name access association are in the same account."
    ), f"unexpected message: {message!r}"

    # the association must remain intact, not removed by the rejected reject call
    items = apigw.get_domain_name_access_associations().get("items", [])
    assert any(item["domainNameAccessAssociationArn"] == assoc_arn for item in items), (
        "association must still exist after a rejected RejectDomainNameAccessAssociation call"
    )

    # Positive control: Delete works, so a target refusing every call cannot pass by accident.
    apigw.delete_domain_name_access_association(domainNameAccessAssociationArn=assoc_arn)
    items_after = apigw.get_domain_name_access_associations().get("items", [])
    assert not any(item["domainNameAccessAssociationArn"] == assoc_arn for item in items_after), (
        "association must be gone after DeleteDomainNameAccessAssociation"
    )


_TEARDOWN_RETRY_S = 300.0
_TEARDOWN_RETRY_CODES = (
    "TooManyRequestsException", "ThrottlingException", "ConflictException", "ResourceInUseException",
    "RequestLimitExceeded",
)


def _safe(fn, *gone: str) -> None:
    """Teardown: done when fn succeeds or answers a `gone` code; retry throttling and in-use
    refusals every 2 s for a bounded window, and raise everything else."""
    deadline = time.monotonic() + _TEARDOWN_RETRY_S
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in gone:
                return
            if code not in _TEARDOWN_RETRY_CODES or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _error(fn):
    """Call fn(), which real AWS refuses; return the ClientError's (Code, Message).
    An unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("real AWS refuses this call, but it SUCCEEDED")


def _capped(ctx, seconds: float) -> float:
    """A poll timeout of `seconds`, bounded by the runner's remaining time when it has a budget."""
    left = ctx.time_left()
    return seconds if left is None else min(seconds, left)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


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


def _import_cert(ctx, common_name: str) -> str:
    cert_pem, key_pem = _self_signed_cert_pem(common_name)
    acm = ctx.client("acm")
    resp = acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem)
    cert_arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _safe(lambda: acm.delete_certificate(CertificateArn=cert_arn), "ResourceNotFoundException"))
    return cert_arn


def _create_private_domain(ctx) -> dict:
    apigw = ctx.client("apigateway")
    domain_name = f"{ctx.unique_name('sim2real-priv-')}.internal.test".lower()
    cert_arn = _import_cert(ctx, domain_name)
    resp = apigw.create_domain_name(
        domainName=domain_name,
        certificateArn=cert_arn,
        endpointConfiguration={"types": ["PRIVATE"]},
    )
    domain_name_id = resp.get("domainNameId")
    ctx.on_cleanup(
        lambda: _safe(
            lambda: apigw.delete_domain_name(domainName=domain_name, domainNameId=domain_name_id),
            "NotFoundException",
        )
    )
    return {"name": domain_name, "arn": resp["domainNameArn"]}


def _create_execute_api_vpce(ctx) -> str:
    ec2 = ctx.client("ec2")

    vpc_id = ec2.create_vpc(CidrBlock="10.121.2.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id), "InvalidVpcID.NotFound"))

    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.121.2.0/24")["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id), "InvalidSubnetID.NotFound"))

    sg_id = ec2.create_security_group(
        VpcId=vpc_id,
        GroupName=ctx.unique_name("sim2real-sg-"),
        Description="sim2real behavioral fidelity test security group",
    )["GroupId"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id), "InvalidGroup.NotFound"))

    vpce_id = ec2.create_vpc_endpoint(
        VpcId=vpc_id,
        ServiceName=f"com.amazonaws.{ctx.region}.execute-api",
        VpcEndpointType="Interface",
        SubnetIds=[subnet_id],
        SecurityGroupIds=[sg_id],
        PrivateDnsEnabled=False,
    )["VpcEndpoint"]["VpcEndpointId"]

    def _delete_vpce():
        # DeleteVpcEndpoints reports per-endpoint failures in Unsuccessful, not as an error.
        failed = ec2.delete_vpc_endpoints(VpcEndpointIds=[vpce_id]).get("Unsuccessful", [])
        if any(f["Error"]["Code"] not in _VPCE_GONE for f in failed):
            raise RuntimeError(f"DeleteVpcEndpoints({vpce_id}) failed: {failed!r}")
        _poll_until(
            lambda: _vpce_state(ec2, vpce_id),
            lambda state: state in (None, "deleted", "deleting"),
            timeout_s=90,
            interval_s=2,
        )

    ctx.on_cleanup(lambda: _safe(_delete_vpce))

    try:
        _poll_until(
            lambda: _vpce_state(ec2, vpce_id),
            lambda state: state == "available",
            timeout_s=_capped(ctx, 300),
            interval_s=2,
        )
    except AssertionError as exc:
        raise AssertionError(f"VPC endpoint never became available: {exc}") from exc

    return vpce_id


_VPCE_GONE = ("InvalidVpcEndpointId.NotFound", "InvalidVpcEndpoint.NotFound")


def _vpce_state(ec2, vpce_id):
    try:
        return ec2.describe_vpc_endpoints(VpcEndpointIds=[vpce_id])["VpcEndpoints"][0]["State"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] in _VPCE_GONE:
            return None
        raise


# Resources in a VPC delete asynchronously and leave AWS-managed ENIs behind for a while, so an
# immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. Teardown
# waits (bounded) for those ENIs, retries DependencyViolation, then raises naming any still attached.
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
