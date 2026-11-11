"""create-domain-name-access-association-invalid-source-rejected."""
from __future__ import annotations

import re
import subprocess
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "create-domain-name-access-association-invalid-source-rejected"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDomainNameAccessAssociation accepts a real VPC endpoint as source (positive control),
    then rejects a malformed VPC endpoint id with BadRequestException and creates nothing."""
    apigw = ctx.client("apigateway")
    vpce_id = _create_execute_api_vpc_endpoint(ctx)
    domain, domain_arn = _create_private_domain(ctx, vpce_id)

    # positive control: a real VPCE id is accepted and produces a listable association
    created = _call_retrying_throttle(lambda: apigw.create_domain_name_access_association(
        domainNameArn=domain_arn,
        accessAssociationSourceType="VPCE",
        accessAssociationSource=vpce_id,
    ))
    assoc_arn = created["domainNameAccessAssociationArn"]
    ctx.on_cleanup(lambda: _safe_delete_association(apigw, assoc_arn))
    assert created["accessAssociationSource"] == vpce_id, created
    listed = _list_self_associations(apigw)
    assert any(a.get("domainNameAccessAssociationArn") == assoc_arn for a in listed), listed

    apigw.delete_domain_name_access_association(domainNameAccessAssociationArn=assoc_arn)
    gone = _poll_until(
        lambda: _find_association(apigw, assoc_arn), lambda r: r is None, timeout_s=60.0, interval_s=3.0
    )
    assert gone is None, "deleted positive-control association still listed"

    # break: a malformed VPC endpoint id must be rejected, and must create nothing
    code, message = _error(lambda: _call_retrying_throttle(lambda: apigw.create_domain_name_access_association(
        domainNameArn=domain_arn,
        accessAssociationSourceType="VPCE",
        accessAssociationSource="not-a-valid-vpce-id",
    )))
    assert code == "BadRequestException", code
    assert message == "Invalid VPC endpoint ID specified.", f"unexpected BadRequestException message {message!r}"

    listed_after = _list_self_associations(apigw)
    matches = [a for a in listed_after if a.get("domainNameArn") == domain_arn]
    assert matches == [], matches


def _error(fn):
    """Call fn(); return (code, message) of the refusal. A call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _call_retrying_throttle(fn, max_attempts: int = 6):
    """CreateDomainNameAccessAssociation is subject to an account-level rate limit that can
    outlast botocore's own retry budget; retry with bounded backoff on TooManyRequestsException
    rather than treating the throttle as the call's own outcome."""
    delay = 5.0
    for attempt in range(max_attempts):
        try:
            return fn()
        except ClientError as err:
            if err.response["Error"]["Code"] == "TooManyRequestsException" and attempt < max_attempts - 1:
                time.sleep(delay)
                delay = min(delay * 2, 60.0)
                continue
            raise


def _create_domain_name_retrying(apigw, *, max_attempts: int = 6, **kwargs):
    """CreateDomainName is throttled account-wide on real AWS (TooManyRequestsException);
    retry with exponential backoff instead of failing on the first hit."""
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


def _find_association(apigw, arn: str):
    for item in _list_self_associations(apigw):
        if item.get("domainNameAccessAssociationArn") == arn:
            return item
    return None


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last saw {result!r}")
        time.sleep(interval_s)
        result = probe()
    return result


def _dns_label(raw: str) -> str:
    return re.sub(r"[^a-z0-9-]", "-", raw.lower()).strip("-")


def _openssl_self_signed_cert(common_name: str) -> tuple[str, str]:
    import tempfile
    from pathlib import Path

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
    import uuid
    require_tools("openssl")
    cert_pem, key_pem = _openssl_self_signed_cert(common_name)
    acm = ctx.client("acm")
    resp = acm.import_certificate(
        Certificate=cert_pem.encode(),
        PrivateKey=key_pem.encode(),
        Tags=[{"Key": "sim2real-behav", "Value": str(uuid.uuid4())}],
    )
    arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_cert_retrying(acm, arn))
    return arn


def _delete_cert_retrying(acm, arn: str) -> None:
    deadline = time.monotonic() + 60.0
    while True:
        try:
            acm.delete_certificate(CertificateArn=arn)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceInUseException" and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


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
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-apigw-vpce-")}],
            }
        ],
    )
    vpce_id = resp["VpcEndpoint"]["VpcEndpointId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc_endpoints(VpcEndpointIds=[vpce_id]))

    state = _poll_until(
        lambda: ec2.describe_vpc_endpoints(VpcEndpointIds=[vpce_id])["VpcEndpoints"][0]["State"],
        lambda s: s in ("available", "failed"),
        timeout_s=240.0, interval_s=10.0,
    )
    if state != "available":
        raise AssertionError(
            f"execute-api VPC endpoint did not become available (state={state})"
        )
    return vpce_id


def _create_private_domain(ctx, vpce_id: str) -> tuple[str, str]:
    apigw = ctx.client("apigateway")
    domain = _dns_label(ctx.unique_name("sim2real-apigw-assocbad-")) + ".example.com"
    cert_arn = _acm_import_cert(ctx, domain)
    policy = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*",'
        '"Action":"execute-api:Invoke","Resource":["execute-api:/*"]}]}'
    )
    created = _create_domain_name_retrying(
        apigw,
        domainName=domain,
        certificateArn=cert_arn,
        endpointConfiguration={"types": ["PRIVATE"], "vpcEndpointIds": [vpce_id]},
        policy=policy,
        tags={"sim2real-behav": ctx.unique_name("tag-")},
    )
    domain_name_id = created.get("domainNameId")
    lookup_kwargs = {"domainName": domain}
    if domain_name_id:
        lookup_kwargs["domainNameId"] = domain_name_id
    ctx.on_cleanup(lambda: _safe_delete_domain(apigw, lookup_kwargs))
    return domain, created["domainNameArn"]


def _safe_delete_domain(apigw, lookup_kwargs: dict) -> None:
    try:
        apigw.delete_domain_name(**lookup_kwargs)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise


def _safe_delete_association(apigw, arn: str) -> None:
    try:
        apigw.delete_domain_name_access_association(domainNameAccessAssociationArn=arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
