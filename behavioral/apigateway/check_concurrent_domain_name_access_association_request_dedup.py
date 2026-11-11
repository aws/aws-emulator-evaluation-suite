"""concurrent-domain-name-access-association-request-dedup."""
from __future__ import annotations

import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "concurrent-domain-name-access-association-request-dedup"
GROUP = "concurrency"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """N concurrent CreateDomainNameAccessAssociation calls for one private domain name and one
    real VPC-endpoint source dedupe to exactly one: every losing racer is rejected with
    BadRequestException, and the domain ends with exactly one association for that source."""
    apigw = ctx.client("apigateway")

    domain_name = ctx.unique_name("sim2real-behav-domain-").lower() + ".example.com"
    cert_arn = _import_self_signed_certificate(ctx, domain_name)
    domain = _create_domain_name_retrying(
        apigw,
        domainName=domain_name,
        certificateArn=cert_arn,
        endpointConfiguration={"types": ["PRIVATE"]},
        policy=(
            '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*",'
            '"Action":"execute-api:Invoke","Resource":["execute-api:/*"]}]}'
        ),
    )
    domain_arn = domain["domainNameArn"]
    domain_name_id = domain["domainNameId"]
    ctx.on_cleanup(lambda: _safe_delete_domain_name(apigw, domain_name, domain_name_id))

    vpce_id = _create_execute_api_vpc_endpoint(ctx)

    n_racers = 4

    def _associate(_i: int) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        try:
            resp = apigw.create_domain_name_access_association(
                domainNameArn=domain_arn,
                accessAssociationSourceType="VPCE",
                accessAssociationSource=vpce_id,
            )
            return resp, None
        except ClientError as exc:
            return None, exc.response["Error"]

    with ThreadPoolExecutor(max_workers=n_racers) as pool:
        outcomes = list(pool.map(_associate, range(n_racers)))

    successes = [o for o in outcomes if o[0] is not None]
    failures = [o for o in outcomes if o[1] is not None]

    assert len(successes) == 1, (
        f"expected exactly 1 winner among {n_racers} concurrent racers for the same "
        f"domain/source pair, got {len(successes)}: {outcomes}"
    )
    assert len(failures) == n_racers - 1, (
        f"expected {n_racers - 1} losers, got {len(failures)}: {outcomes}"
    )
    for _, error in failures:
        code = error["Code"]
        message = error.get("Message")
        assert code == "BadRequestException", f"unexpected error code on duplicate association: {code}"
        assert message == (
            "The domain name access association between this VPC endpoint and domain name "
            "already exists."
        ), f"unexpected message on duplicate association: {message!r}"

    winner_arn = successes[0][0]["domainNameAccessAssociationArn"]
    ctx.on_cleanup(lambda: _safe_delete_association(apigw, winner_arn))

    associations = apigw.get_domain_name_access_associations(resourceOwner="SELF")["items"]
    matching = [
        a
        for a in associations
        if a["domainNameArn"] == domain_arn and a["accessAssociationSource"] == vpce_id
    ]
    assert len(matching) == 1, f"expected exactly 1 access association for domain/source, got {matching}"
    assert matching[0]["domainNameAccessAssociationArn"] == winner_arn, (
        "the surviving access association must be the one the winning racer created, not a "
        "different or duplicate resource"
    )


# ===== helpers (self-contained) =====
def _openssl_self_signed_cert(common_name: str) -> tuple[bytes, bytes]:
    with tempfile.TemporaryDirectory() as d:
        key_path = Path(d) / "key.pem"
        crt_path = Path(d) / "crt.pem"
        require_tools("openssl")
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", str(key_path), "-out", str(crt_path),
                "-days", "2", "-nodes", "-subj", f"/CN={common_name}",
            ],
            check=True, capture_output=True, timeout=30,
        )
        return crt_path.read_bytes(), key_path.read_bytes()


def _import_self_signed_certificate(ctx, domain_name: str) -> str:
    # A PRIVATE custom domain name still requires a certificate whose CN/SAN covers the
    # domain (CreateDomainName rejects a mismatched cert) -- but that cert only needs to be
    # accepted by ACM, not publicly trusted, since it never terminates untrusted public TLS.
    # A throwaway self-signed cert imported via ACM satisfies this with no external domain
    # ownership or CA infrastructure needed.
    cert_pem, key_pem = _openssl_self_signed_cert(domain_name)
    acm = ctx.client("acm")
    resp = acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem)
    cert_arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_certificate_when_released(acm, cert_arn))
    return cert_arn


def _create_domain_name_retrying(apigw, *, max_attempts: int = 6, **kwargs) -> dict[str, Any]:
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


def _create_execute_api_vpc_endpoint(ctx) -> str:
    """Stand up a minimal VPC + subnet + security group + interface VPC endpoint for
    execute-api, to use as a real accessAssociationSource. A syntactically-valid but
    nonexistent VPCE id does not exercise the dedup path at all: real AWS rejects an
    access association against a nonexistent VPC endpoint with BadRequestException
    before any dedup logic runs, so only a real endpoint reaches the duplicate check."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-dnaa-")

    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]

    try:
        vpc_id = ec2.create_vpc(
            CidrBlock="10.78.0.0/16",
            TagSpecifications=[_tag_spec("vpc", name)],
        )["Vpc"]["VpcId"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "VpcLimitExceeded":
            raise AssertionError(
                "unreachable: account has hit its VPC limit, cannot provision a test VPC"
            ) from exc
        raise
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    # An execute-api interface endpoint defaults to PrivateDnsEnabled, and real AWS rejects that
    # with InvalidParameter ("Enabling private DNS requires both enableDnsSupport and
    # enableDnsHostnames VPC attributes set to true") unless BOTH attributes are on. A freshly
    # created non-default VPC has enableDnsSupport=true but enableDnsHostnames=FALSE, so the
    # hostnames attribute has to be turned on explicitly.
    for attr in ("EnableDnsSupport", "EnableDnsHostnames"):
        ec2.modify_vpc_attribute(VpcId=vpc_id, **{attr: {"Value": True}})

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.78.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=[_tag_spec("subnet", name)],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    sg_id = ec2.create_security_group(
        GroupName=name,
        Description="sim2real behavioral check: execute-api VPCE",
        VpcId=vpc_id,
        TagSpecifications=[_tag_spec("security-group", name)],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_with_retry(ec2, sg_id))

    region = ctx.region
    vpce_id = ec2.create_vpc_endpoint(
        VpcEndpointType="Interface",
        VpcId=vpc_id,
        ServiceName=f"com.amazonaws.{region}.execute-api",
        SubnetIds=[subnet_id],
        SecurityGroupIds=[sg_id],
        TagSpecifications=[_tag_spec("vpc-endpoint", name)],
    )["VpcEndpoint"]["VpcEndpointId"]
    ctx.on_cleanup(lambda: _delete_vpc_endpoint_with_wait(ec2, vpce_id))

    return vpce_id


def _tag_spec(resource_type: str, name: str) -> dict[str, Any]:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _delete_vpc_endpoint_with_wait(ec2, vpce_id: str, timeout_s: float = 300.0) -> None:
    ec2.delete_vpc_endpoints(VpcEndpointIds=[vpce_id])
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            endpoints = ec2.describe_vpc_endpoints(VpcEndpointIds=[vpce_id]).get("VpcEndpoints", [])
        except ClientError as err:
            if "NotFound" in err.response["Error"]["Code"]:
                return
            raise
        if not endpoints or endpoints[0]["State"].lower() == "deleted":
            return
        time.sleep(5)
    raise AssertionError(f"VPC endpoint {vpce_id} not deleted within {timeout_s}s")


def _delete_security_group_with_retry(ec2, sg_id: str, timeout_s: float = 300.0) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_security_group(GroupId=sg_id)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] == "DependencyViolation" and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _delete_quietly_if_gone(fn) -> None:
    """Run a delete; only a resource that is already gone counts as deleted."""
    try:
        fn()
    except ClientError as err:
        if "NotFound" not in err.response["Error"]["Code"]:
            raise


def _safe_delete_domain_name(apigw: Any, domain_name: str, domain_name_id: str) -> None:
    # A PRIVATE domain name is addressed by name AND id; by name alone the delete targets a
    # public domain of that name and answers NotFound.
    _delete_quietly_if_gone(
        lambda: apigw.delete_domain_name(domainName=domain_name, domainNameId=domain_name_id)
    )


def _delete_certificate_when_released(acm: Any, cert_arn: str, timeout_s: float = 300.0) -> None:
    """ACM reports a certificate in use for a while after its domain name is deleted."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            acm.delete_certificate(CertificateArn=cert_arn)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code == "ResourceInUseException" and time.monotonic() < deadline:
                time.sleep(10)
                continue
            raise


def _safe_delete_association(apigw: Any, assoc_arn: str) -> None:
    _delete_quietly_if_gone(
        lambda: apigw.delete_domain_name_access_association(domainNameAccessAssociationArn=assoc_arn)
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
