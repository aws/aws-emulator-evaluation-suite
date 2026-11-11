"""delete-domain-name-with-active-association-succeeds."""
from __future__ import annotations

import datetime
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-domain-name-with-active-association-succeeds"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteDomainName on a PRIVATE custom domain name is not gated on its domain-name
    access associations: the delete succeeds, the domain is gone (NotFoundException), and the
    association is left behind as an orphan rather than refused or cascade-deleted."""
    apigw = ctx.client("apigateway")

    domain = _create_private_domain(ctx)
    vpce_id = _create_execute_api_vpce(ctx)

    assoc = apigw.create_domain_name_access_association(
        domainNameArn=domain["arn"],
        accessAssociationSourceType="VPCE",
        accessAssociationSource=vpce_id,
        tags={"Name": domain["name"]},
    )
    assoc_arn = assoc["domainNameAccessAssociationArn"]
    ctx.on_cleanup(
        _teardown(
            lambda: apigw.delete_domain_name_access_association(
                domainNameAccessAssociationArn=assoc_arn
            ),
            "NotFoundException",
        )
    )

    # Precondition, read back independently of the create call's own echo: the association
    # really is attached to this domain before the delete under test.
    assert _assoc_arns(apigw).count(assoc_arn) == 1, (
        f"access association {assoc_arn!r} is not listed before the delete: "
        f"{_assoc_arns(apigw)!r}"
    )

    # The call under test. It is NOT refused.
    _retry_throttled(
        lambda: apigw.delete_domain_name(
            domainName=domain["name"], domainNameId=domain["id"]
        ),
        "DeleteDomainName",
    )

    # The delete took full effect: the domain is gone, not merely detached.
    gone = _error_code(
        lambda: apigw.get_domain_name(domainName=domain["name"], domainNameId=domain["id"])
    )
    assert gone == ("NotFoundException", "Invalid domain name identifier specified"), (
        f"expected NotFoundException reading the deleted private domain, got {gone!r}"
    )

    # The association is orphaned rather than cascade-removed with its domain.
    assert assoc_arn in _assoc_arns(apigw), (
        f"access association {assoc_arn!r} was cascade-deleted with its domain; real AWS "
        f"leaves it listed. Now listed: {_assoc_arns(apigw)!r}"
    )


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` codes mean gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error_code(fn):
    """Call fn() and return its (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to fail, but it SUCCEEDED and returned {result!r}")


def _delete_retrying(fn, deadline: float, interval_s: float = 2.0) -> None:
    """Best-effort delete that retries on DependencyViolation until the SHARED *deadline*.

    A shared deadline keeps the first delete from starving the ones behind it.
    """
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            if (
                exc.response["Error"]["Code"] != "DependencyViolation"
                or time.monotonic() >= deadline
            ):
                return
            time.sleep(interval_s)
        except Exception:
            return


def _retry_throttled(fn, label: str, timeout_s: float = 240.0, interval_s: float = 5.0):
    """Call fn(), backing off on the account-wide DomainName API throttle only.

    Create/Delete/UpdateDomainName share one account-level throttle; every other error is
    re-raised so a retry never hides the behaviour under test.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if (
                exc.response["Error"]["Code"] != "TooManyRequestsException"
                or time.monotonic() >= deadline
            ):
                raise
            time.sleep(interval_s)


def _assoc_arns(apigw) -> list[str]:
    """Every domain-name access association ARN in the account, read independently."""
    arns: list[str] = []
    position = None
    while True:
        kwargs = {"position": position} if position else {}
        page = apigw.get_domain_name_access_associations(**kwargs)
        arns.extend(
            item["domainNameAccessAssociationArn"] for item in page.get("items", [])
        )
        position = page.get("position")
        if not position:
            return arns


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
    resp = acm.import_certificate(
        Certificate=cert_pem,
        PrivateKey=key_pem,
        Tags=[{"Key": "Name", "Value": common_name}],
    )
    cert_arn = resp["CertificateArn"]
    ctx.on_cleanup(
        _teardown(lambda: acm.delete_certificate(CertificateArn=cert_arn), "ResourceNotFoundException")
    )
    return cert_arn


def _create_private_domain(ctx) -> dict:
    apigw = ctx.client("apigateway")
    domain_name = f"{ctx.unique_name('sim2real-priv-')}.internal.test".lower()
    cert_arn = _import_cert(ctx, domain_name)
    # PRIVATE domain names take `certificateArn` and reject `regionalCertificateArn`.
    resp = _retry_throttled(
        lambda: apigw.create_domain_name(
            domainName=domain_name,
            certificateArn=cert_arn,
            endpointConfiguration={"types": ["PRIVATE"]},
            tags={"Name": domain_name},
        ),
        "CreateDomainName",
    )
    domain_name_id = resp["domainNameId"]
    ctx.on_cleanup(
        _teardown(
            lambda: apigw.delete_domain_name(
                domainName=domain_name, domainNameId=domain_name_id
            ),
            "NotFoundException",
        )
    )
    return {"name": domain_name, "arn": resp["domainNameArn"], "id": domain_name_id}


def _tag_spec(resource_type: str, name: str) -> list[dict]:
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}]


def _create_execute_api_vpce(ctx) -> str:
    """An available execute-api interface endpoint in the run's shared network.

    The shared network avoids the VPC quota; teardown only has to outlive the ENI for one SG.
    """
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-domain-assoc-")

    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    assert vpcs, "no shared network VPC in this account/region to attach the execute-api endpoint to"
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        ]
    )["Subnets"]
    assert subnets, f"shared network {vpc_id} has no network subnet to place the endpoint in"
    subnet_id = subnets[0]["SubnetId"]
    sg_id = ec2.create_security_group(
        VpcId=vpc_id,
        GroupName=ctx.unique_name("sim2real-sg-"),
        Description="sim2real behavioral fidelity test security group",
        TagSpecifications=_tag_spec("security-group", name),
    )["GroupId"]

    vpce_id = ec2.create_vpc_endpoint(
        VpcId=vpc_id,
        ServiceName=f"com.amazonaws.{ctx.region}.execute-api",
        VpcEndpointType="Interface",
        SubnetIds=[subnet_id],
        SecurityGroupIds=[sg_id],
        PrivateDnsEnabled=False,
        TagSpecifications=_tag_spec("vpc-endpoint", name),
    )["VpcEndpoint"]["VpcEndpointId"]

    # One ordered cleanup sharing a 50s budget to fit the 60s teardown window: drop the endpoint,
    # wait for it, then retry the security group while its ENI releases.
    def _delete_ec2_chain():
        deadline = time.monotonic() + 50.0
        _teardown(
            lambda: ec2.delete_vpc_endpoints(VpcEndpointIds=[vpce_id]),
            "InvalidVpcEndpointId.NotFound",
        )()
        while time.monotonic() < deadline:
            if _vpce_state(ec2, vpce_id) in (None, "deleted"):
                break
            time.sleep(2)
        _delete_retrying(lambda: ec2.delete_security_group(GroupId=sg_id), deadline)

    ctx.on_cleanup(_delete_ec2_chain)

    try:
        _poll_until(
            lambda: _vpce_state(ec2, vpce_id),
            lambda state: state == "available",
            timeout_s=300,
            interval_s=10,
        )
    except AssertionError as exc:
        raise AssertionError(
            f"VPC endpoint never became available: {exc}"
        ) from exc

    return vpce_id


def _vpce_state(ec2, vpce_id):
    try:
        return ec2.describe_vpc_endpoints(VpcEndpointIds=[vpce_id])["VpcEndpoints"][0]["State"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("InvalidVpcEndpointId.NotFound",):
            return None
        raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
