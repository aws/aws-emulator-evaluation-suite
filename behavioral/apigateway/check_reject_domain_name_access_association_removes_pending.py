"""reject-domain-name-access-association-removes-pending."""
from __future__ import annotations

import json
import subprocess
import tempfile
import time
from pathlib import Path

from behavioral_harness import tags
from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

CHECK = "reject-domain-name-access-association-removes-pending"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RejectDomainNameAccessAssociation is refused with BadRequestException for a
    same-account association (real AWS only lets the domain owner reject an
    association requested by a *different* account) and leaves it in the active list."""
    apigw = ctx.client("apigateway")
    vpce = _create_execute_api_vpc_endpoint(ctx)
    domain = _apigw_test_domain(ctx, "reject")
    cert_arn = _acm_import_cert(ctx, domain)

    policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": "*", "Action": "execute-api:Invoke", "Resource": ["execute-api:/*"]},
            {
                "Effect": "Deny", "Principal": "*", "Action": "execute-api:Invoke",
                "Resource": ["execute-api:/*"],
                "Condition": {"StringNotEquals": {"aws:SourceVpce": vpce["vpce_id"]}},
            },
        ],
    })
    created_domain = _create_domain_name_retrying(
        apigw,
        domainName=domain,
        certificateArn=cert_arn,
        endpointConfiguration={"types": ["PRIVATE"]},
        policy=policy,
    )
    domain_name_id = created_domain.get("domainNameId")
    ctx.on_cleanup(lambda: _safe_delete_domain(apigw, domain, domain_name_id))
    domain_arn = created_domain["domainNameArn"]

    created_assoc = apigw.create_domain_name_access_association(
        domainNameArn=domain_arn,
        accessAssociationSourceType="VPCE",
        accessAssociationSource=vpce["vpce_id"],
    )
    assoc_arn = created_assoc["domainNameAccessAssociationArn"]
    ctx.on_cleanup(lambda: _safe_delete_association(apigw, assoc_arn))

    listed = _list_self_associations(apigw)
    assert any(a.get("domainNameAccessAssociationArn") == assoc_arn for a in listed), listed

    code, message = _error(lambda: apigw.reject_domain_name_access_association(
        domainNameAccessAssociationArn=assoc_arn,
        domainNameArn=domain_arn,
    ))
    assert code == "BadRequestException", code
    assert message == (
        "Cannot reject the domain name access association when the private custom domain and "
        "domain name access association are in the same account."
    ), f"unexpected message: {message!r}"

    # a same-account association is not "pending" approval, so rejecting it is
    # refused and the association remains untouched in the active list.
    listed_after = _list_self_associations(apigw)
    remaining = [a for a in listed_after if a.get("domainNameAccessAssociationArn") == assoc_arn]
    assert len(remaining) == 1, listed_after

    # Positive control: DeleteDomainNameAccessAssociation (the documented same-account removal
    # path) succeeds on the identical resource, so the refusal above is specific to Reject and
    # not a sign that nothing can remove this association.
    apigw.delete_domain_name_access_association(domainNameAccessAssociationArn=assoc_arn)
    listed_final = _list_self_associations(apigw)
    assert not any(a.get("domainNameAccessAssociationArn") == assoc_arn for a in listed_final), listed_final


def _apigw_test_domain(ctx, label: str) -> str:
    base = ctx.unique_name(f"sim2real-apigw-{label}-").rstrip("-").lower()
    return f"{base}.example.com"


def _openssl_self_signed_cert(common_name: str) -> tuple[str, str]:
    with tempfile.TemporaryDirectory() as d:
        key_path = Path(d) / "key.pem"
        crt_path = Path(d) / "crt.pem"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", str(key_path), "-out", str(crt_path),
                "-days", "2", "-nodes", "-subj", f"/CN={common_name}",
            ],
            check=True, capture_output=True, timeout=30,
        )
        return crt_path.read_text(), key_path.read_text()


def _acm_import_cert(ctx, common_name: str) -> str:
    require_tools("openssl")
    cert_pem, key_pem = _openssl_self_signed_cert(common_name)
    acm = ctx.client("acm")
    resp = acm.import_certificate(Certificate=cert_pem.encode(), PrivateKey=key_pem.encode())
    arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_certificate_when_released(acm, arn))
    return arn


def _delete_certificate_when_released(acm, cert_arn: str, timeout_s: float = 300.0) -> None:
    """ACM keeps a certificate in use for a while after its custom domain is deleted, so retry
    ResourceInUseException within a bounded window; any other error propagates."""
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            acm.delete_certificate(CertificateArn=cert_arn)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(10)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            return result
        time.sleep(interval_s)
        result = probe()
    return result


def _error(fn):
    """Call fn(), which real AWS refuses; return the ClientError's (Code, Message).
    An unexpected success raises."""
    from botocore.exceptions import ClientError
    try:
        fn()
    except ClientError as err:
        e = err.response.get("Error", {})
        return e.get("Code"), e.get("Message")
    raise AssertionError("real AWS refuses this call, but it SUCCEEDED")


def _create_execute_api_vpc_endpoint(ctx) -> dict:
    ec2 = ctx.client("ec2")
    tag = ctx.unique_name("sim2real-apigw-vpce-")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.222.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": tag}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.222.1.0/24",
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": tag}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    sg_id = ec2.create_security_group(
        GroupName=tag, Description="sim2real apigw vpc endpoint sg", VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": tag}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=sg_id))

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
        try:
            ec2.delete_vpc_endpoints(VpcEndpointIds=[vpce_id])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidVpcEndpointId.NotFound":
                raise
            return
        _poll_until(
            lambda: _vpce_items(ec2, vpce_id),
            lambda items: not items or items[0]["State"] == "deleted",
            timeout_s=120, interval_s=5,
        )

    ctx.on_cleanup(_cleanup_vpce)

    state = _poll_until(
        lambda: ec2.describe_vpc_endpoints(VpcEndpointIds=[vpce_id])["VpcEndpoints"][0]["State"],
        lambda s: s in ("available", "failed"),
        timeout_s=300, interval_s=10,
    )
    if state != "available":
        raise AssertionError(f"VPC endpoint did not become available (state={state})")
    return {"vpc_id": vpc_id, "subnet_id": subnet_id, "sg_id": sg_id, "vpce_id": vpce_id}


def _vpce_items(ec2, vpce_id: str) -> list:
    """The endpoint's describe items; an endpoint that is already gone reads as empty."""
    from botocore.exceptions import ClientError
    try:
        return ec2.describe_vpc_endpoints(VpcEndpointIds=[vpce_id]).get("VpcEndpoints", [])
    except ClientError as err:
        if err.response["Error"]["Code"] == "InvalidVpcEndpointId.NotFound":
            return []
        raise


def _create_domain_name_retrying(apigw, *, max_attempts: int = 6, **kwargs):
    """CreateDomainName is throttled account-wide on real AWS (TooManyRequestsException);
    retry with exponential backoff instead of failing on the first hit."""
    from botocore.exceptions import ClientError
    delay = 5.0
    for attempt in range(max_attempts):
        try:
            return apigw.create_domain_name(**kwargs)
        except ClientError as err:
            if err.response["Error"]["Code"] == "TooManyRequestsException" and attempt < max_attempts - 1:
                time.sleep(delay)
                delay = min(delay * 2, 60.0)
                continue
            raise


def _list_self_associations(apigw) -> list[dict]:
    out: list[dict] = []
    position = None
    while True:
        kwargs = {"resourceOwner": "SELF"}
        if position:
            kwargs["position"] = position
        page = apigw.get_domain_name_access_associations(**kwargs)
        out.extend(page.get("items", []))
        position = page.get("position")
        if not position:
            return out


def _safe_delete_domain(apigw, domain: str, domain_name_id: str | None) -> None:
    # A PRIVATE custom domain is addressed by name AND id; a name-only delete misses it.
    try:
        apigw.delete_domain_name(domainName=domain, domainNameId=domain_name_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _safe_delete_association(apigw, assoc_arn: str) -> None:
    try:
        apigw.delete_domain_name_access_association(domainNameAccessAssociationArn=assoc_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
