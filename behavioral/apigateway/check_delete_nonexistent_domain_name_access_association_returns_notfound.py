"""delete-nonexistent-domain-name-access-association-returns-notfound."""
from __future__ import annotations

import datetime
import re
import time

from behavioral_harness import tags

CHECK = "delete-nonexistent-domain-name-access-association-returns-notfound"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDomainNameAccessAssociation on an already-deleted association ARN returns
    NotFoundException with AWS's exact message, and the ARN stays absent from the listing."""
    apigw = ctx.client("apigateway")
    vpce_id = _create_execute_api_vpc_endpoint(ctx)
    domain, domain_arn = _create_private_domain(ctx, vpce_id)

    # A hand-built association ARN fails format validation (BadRequestException) before the
    # existence check, so a real association is created and deleted to get a well-formed dead ARN.
    assoc = _create_domain_name_access_association_retrying(
        apigw,
        domainNameArn=domain_arn,
        accessAssociationSource=vpce_id,
        accessAssociationSourceType="VPCE",
    )
    arn = assoc["domainNameAccessAssociationArn"]
    found = _find_association(apigw, arn)
    assert found is not None, f"expected {arn} in get_domain_name_access_associations, found nothing"

    apigw.delete_domain_name_access_association(domainNameAccessAssociationArn=arn)
    gone = _poll_until(
        lambda: _find_association(apigw, arn), lambda r: r is None, timeout_s=60.0, interval_s=3.0
    )
    assert gone is None, "deleted association still listed"

    code, message = _client_error(
        lambda: apigw.delete_domain_name_access_association(domainNameAccessAssociationArn=arn)
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == "This private custom domain name doesn't have any domain name access associations.", message

    # the (now-deleted) association is absent from the account's association list
    associations = _list_access_associations(apigw)
    listed_arns = {a.get("domainNameAccessAssociationArn") for a in associations}
    assert arn not in listed_arns, f"expected {arn} absent from get_domain_name_access_associations, still listed"


def _client_error(fn):
    """Call fn(); return the (code, message) of its botocore error. An unexpected SUCCESS raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _list_access_associations(apigw):
    items = []
    kwargs = {}
    while True:
        resp = apigw.get_domain_name_access_associations(**kwargs)
        items.extend(resp.get("items", []))
        position = resp.get("position")
        if not position:
            break
        kwargs["position"] = position
    return items


def _find_association(apigw, arn: str):
    kwargs = {}
    for _ in range(20):
        resp = apigw.get_domain_name_access_associations(**kwargs)
        for item in resp.get("items", []):
            if item["domainNameAccessAssociationArn"] == arn:
                return item
        marker = resp.get("position")
        if not marker:
            return None
        kwargs["position"] = marker
    return None


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_domain_name_access_association_retrying(apigw, timeout_s: float = 180.0, interval_s: float = 10.0, **kwargs):
    """CreateDomainNameAccessAssociation has an account-level rate limit that can outlast
    botocore's retries; retry TooManyRequestsException with a longer bounded backoff."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return apigw.create_domain_name_access_association(**kwargs)
        except ClientError as err:
            if err.response["Error"]["Code"] == "TooManyRequestsException" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _dns_label(raw: str) -> str:
    return re.sub(r"[^a-z0-9-]", "-", raw.lower()).strip("-")


def _generate_self_signed_cert(common_name: str):
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
        .not_valid_after(now + datetime.timedelta(days=3))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    return cert_pem, key_pem


def _delete_cert_retrying(acm, arn: str) -> None:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 60.0
    while True:
        try:
            acm.delete_certificate(CertificateArn=arn)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] in ("ResourceInUseException",) and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _import_self_signed_cert(ctx, common_name: str) -> str:
    import uuid

    acm = ctx.client("acm")
    cert_pem, key_pem = _generate_self_signed_cert(common_name)
    resp = acm.import_certificate(
        Certificate=cert_pem.encode(),
        PrivateKey=key_pem.encode(),
        Tags=[{"Key": "sim2real-behav", "Value": str(uuid.uuid4())}],
    )
    arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_cert_retrying(acm, arn))
    return arn


def _create_execute_api_vpc_endpoint(ctx) -> str:
    

    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to create an execute-api VPC endpoint")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets available for a VPC endpoint")
    subnet_id = subnets[0]["SubnetId"]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("shared network has no default security group")
    sg_id = sgs[0]["GroupId"]

    resp = ec2.create_vpc_endpoint(
        VpcEndpointType="Interface",
        ServiceName=f"com.amazonaws.{ctx.region}.execute-api",
        VpcId=vpc_id,
        SubnetIds=[subnet_id],
        SecurityGroupIds=[sg_id],
        PrivateDnsEnabled=False,
        TagSpecifications=[
            {
                "ResourceType": "vpc-endpoint",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-vpce-")}],
            }
        ],
    )
    vpce_id = resp["VpcEndpoint"]["VpcEndpointId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc_endpoints(VpcEndpointIds=[vpce_id]))

    state = _poll_until(
        lambda: ec2.describe_vpc_endpoints(VpcEndpointIds=[vpce_id])["VpcEndpoints"][0]["State"],
        lambda s: s in ("available", "failed"),
        timeout_s=240.0,
        interval_s=10.0,
    )
    if state != "available":
        raise AssertionError(
            f"execute-api VPC endpoint did not become available (state={state})"
        )
    return vpce_id


def _create_private_domain(ctx, vpce_id: str):
    apigw = ctx.client("apigateway")
    domain = _dns_label(ctx.unique_name("sim2real-dnaadom-")) + ".internal.example.com"
    cert_arn = _import_self_signed_cert(ctx, domain)
    created = apigw.create_domain_name(
        domainName=domain,
        certificateArn=cert_arn,
        endpointConfiguration={"types": ["PRIVATE"], "vpcEndpointIds": [vpce_id]},
    )
    # PRIVATE domain names are assigned a domainNameId; GetDomainName/DeleteDomainName then
    # require it too once the domain has one.
    domain_name_id = created.get("domainNameId")
    lookup_kwargs = {"domainName": domain}
    if domain_name_id:
        lookup_kwargs["domainNameId"] = domain_name_id

    def _cleanup_domain():
        from botocore.exceptions import ClientError

        try:
            apigw.delete_domain_name(**lookup_kwargs)
        except ClientError as err:
            if err.response["Error"]["Code"] != "NotFoundException":
                raise

    ctx.on_cleanup(_cleanup_domain)
    got = apigw.get_domain_name(**lookup_kwargs)
    return domain, got["domainNameArn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
