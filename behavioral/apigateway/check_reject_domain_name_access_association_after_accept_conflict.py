"""reject-domain-name-access-association-after-accept-conflict."""
from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Callable

from botocore.exceptions import ClientError

CHECK = "reject-domain-name-access-association-after-accept-conflict"
GROUP = "concurrency"
SERVICES = ["apigateway"]

from behavioral_harness import tags
from fidelity_tests_runner import require_tools


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RejectDomainNameAccessAssociation on a same-account association fails BadRequestException and
    leaves it in place; DeleteDomainNameAccessAssociation then removes it."""
    apigw = ctx.client("apigateway")
    ec2 = ctx.client("ec2")
    acm = ctx.client("acm")
    region = ctx.region

    vpc_id, subnet_id = _pick_vpc_and_subnet(ec2, ctx=ctx)
    front_vpce_id = _create_execute_api_vpce(ctx, ec2, region, vpc_id, subnet_id, "front")
    consumer_vpce_id = _create_execute_api_vpce(ctx, ec2, region, vpc_id, subnet_id, "consumer")

    domain_name = ctx.unique_name("sim2real-behav-pd-").lower() + ".private.internal"
    cert_arn = _import_self_signed_cert(ctx, acm, domain_name)

    created = apigw.create_domain_name(
        domainName=domain_name,
        certificateArn=cert_arn,
        endpointConfiguration={"types": ["PRIVATE"], "vpcEndpointIds": [front_vpce_id]},
    )
    domain_name_id = created.get("domainNameId")
    domain_arn = created["domainNameArn"]

    def _cleanup_domain() -> None:
        _ignore_not_found(lambda: apigw.delete_domain_name(domainName=domain_name, domainNameId=domain_name_id))
    ctx.on_cleanup(_cleanup_domain)

    domain_status = _poll_until(
        lambda: apigw.get_domain_name(domainName=domain_name, domainNameId=domain_name_id)["domainNameStatus"],
        lambda s: s in ("AVAILABLE", "FAILED"),
        timeout_s=240.0,
        interval_s=10.0,
    )
    assert domain_status == "AVAILABLE", f"domain name did not become AVAILABLE (status={domain_status!r})"

    assoc = apigw.create_domain_name_access_association(
        domainNameArn=domain_arn, accessAssociationSourceType="VPCE", accessAssociationSource=consumer_vpce_id,
    )
    assoc_arn = assoc["domainNameAccessAssociationArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(
        lambda: apigw.delete_domain_name_access_association(domainNameAccessAssociationArn=assoc_arn)
    ))

    # Reject only applies to associations from a different account; the VPC endpoint here is in
    # the domain's own account, so AWS returns BadRequestException rather than ConflictException.
    code, message = _error(lambda: apigw.reject_domain_name_access_association(
        domainNameAccessAssociationArn=assoc_arn, domainNameArn=domain_arn,
    ))
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    assert message == (
        "Cannot reject the domain name access association when the private custom domain and "
        "domain name access association are in the same account."
    ), f"unexpected message: {message!r}"

    arns = {i["domainNameAccessAssociationArn"] for i in apigw.get_domain_name_access_associations()["items"]}
    assert assoc_arn in arns, "association was unexpectedly removed by a rejected RejectDomainNameAccessAssociation call"

    # Positive control: the owner can still revoke it via DeleteDomainNameAccessAssociation.
    apigw.delete_domain_name_access_association(domainNameAccessAssociationArn=assoc_arn)
    arns_after = {i["domainNameAccessAssociationArn"] for i in apigw.get_domain_name_access_associations()["items"]}
    assert assoc_arn not in arns_after, "association was not removed by DeleteDomainNameAccessAssociation"


def _pick_vpc_and_subnet(ec2: Any, *, ctx) -> tuple[str, str]:
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("no subnet available in VPC to create the execute-api VPC endpoints")
    return vpc_id, subnets[0]["SubnetId"]


def _create_execute_api_vpce(
    ctx, ec2: Any, region: str, vpc_id: str, subnet_id: str, role: str, *, private_dns_enabled: bool = False,
) -> str:
    name = ctx.unique_name(f"sim2real-behav-vpce-{role}-")
    resp = ec2.create_vpc_endpoint(
        VpcEndpointType="Interface",
        VpcId=vpc_id,
        ServiceName=f"com.amazonaws.{region}.execute-api",
        SubnetIds=[subnet_id],
        PrivateDnsEnabled=private_dns_enabled,
        TagSpecifications=[{"ResourceType": "vpc-endpoint", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    vpce_id = resp["VpcEndpoint"]["VpcEndpointId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: ec2.delete_vpc_endpoints(VpcEndpointIds=[vpce_id])))
    return vpce_id


def _import_self_signed_cert(ctx, acm: Any, domain_name: str) -> str:
    require_tools("openssl")
    with tempfile.TemporaryDirectory() as tmp:
        key_path = str(Path(tmp) / "key.pem")
        cert_path = str(Path(tmp) / "cert.pem")
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", key_path, "-out", cert_path, "-days", "365",
                "-subj", f"/CN={domain_name}",
            ],
            check=True, capture_output=True,
        )
        cert_bytes = Path(cert_path).read_bytes()
        key_bytes = Path(key_path).read_bytes()

    resp = acm.import_certificate(Certificate=cert_bytes, PrivateKey=key_bytes)
    cert_arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: acm.delete_certificate(CertificateArn=cert_arn)))
    return cert_arn


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """(Error.Code, Error.Message) of the ClientError fn raises; an unexpected success fails."""
    try:
        fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("real AWS refuses this call, but it SUCCEEDED")


def _ignore_not_found(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") != "NotFoundException":
            raise


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
