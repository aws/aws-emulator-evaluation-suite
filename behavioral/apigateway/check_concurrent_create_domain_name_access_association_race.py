"""concurrent-create-domain-name-access-association-race."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-domain-name-access-association-race"
GROUP = "concurrency"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent CreateDomainNameAccessAssociation calls for the same private domain/source
    pair: exactly one succeeds, the other is refused with BadRequestException (already exists),
    and the persisted association list holds exactly one entry."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    apigw = ctx.client("apigateway")
    domain = _provision_private_domain(ctx, apigw, teardown_deadline)

    def _attempt(_: int) -> tuple[str, str, str]:
        # A throttled racer is not an answer to the race: retry it every 2 s within the run budget.
        deadline = time.monotonic() + min(120.0, ctx.time_left())
        while True:
            try:
                resp = apigw.create_domain_name_access_association(
                    domainNameArn=domain["domain_name_arn"],
                    accessAssociationSourceType="VPCE",
                    accessAssociationSource=domain["vpce_id"],
                )
                return ("ok", resp["domainNameAccessAssociationArn"], "")
            except _client_error_type() as exc:
                err = exc.response["Error"]
                if err["Code"] != "TooManyRequestsException" or time.monotonic() >= deadline:
                    return ("err", err["Code"], err.get("Message", ""))
            time.sleep(2)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(_attempt, range(2)))
    for status, arn, _ in results:
        if status == "ok":
            ctx.on_cleanup(lambda a=arn: _teardown(
                teardown_deadline,
                lambda: apigw.delete_domain_name_access_association(domainNameAccessAssociationArn=a),
                gone=("NotFoundException",),
                retry=("TooManyRequestsException",),
            ))

    oks = [r for r in results if r[0] == "ok"]
    errs = [r for r in results if r[0] == "err"]
    assert len(oks) == 1, f"expected exactly one association winner, got {results}"
    assert len(errs) == 1, f"expected exactly one rejected racer, got {results}"
    err_code, err_message = errs[0][1], errs[0][2]
    # AWS reports the duplicate as BadRequestException, not ConflictException (ConflictException
    # is modeled for the operation but is not what a same-pair duplicate actually returns).
    # A message check separates this
    # specific "already exists" refusal from any other malformed-request BadRequestException.
    assert err_code == "BadRequestException", (
        f"losing racer did not get BadRequestException, got {err_code}: {err_message}"
    )
    assert err_message == "The domain name access association between this VPC endpoint and domain name already exists.", (
        f"BadRequestException did not report a duplicate access association, got: {err_message!r}"
    )

    winner_arn = oks[0][1]

    assocs = apigw.get_domain_name_access_associations()["items"]
    matching = [a for a in assocs if a["domainNameArn"] == domain["domain_name_arn"]]
    assert len(matching) == 1, (
        f"expected exactly one persisted access association for the domain, found "
        f"{matching}"
    )
    assert matching[0]["domainNameAccessAssociationArn"] == winner_arn, (
        "persisted association does not match the racer that received the successful "
        "response"
    )


# ===== helpers (self-contained) =====
def _client_error_type():
    from botocore.exceptions import ClientError

    return ClientError


# budget.cleanup_timeout for behavioral/apigateway, one deadline shared by every teardown of a run.
_TEARDOWN_RETRY_S = 900.0


def _teardown(teardown_deadline, fn, gone=(), retry=()) -> None:
    """Teardown: done when fn succeeds or answers a `gone` code; retry the `retry` codes every
    2 s to the shared cleanup deadline, and raise everything else."""
    deadline = teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_RETRY_S - 120.0)
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in gone:
                return
            if code not in retry or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _tag_spec(resource_type: str, name: str) -> list[dict[str, Any]]:
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}]


def _import_self_signed_certificate(ctx, common_name: str, teardown_deadline) -> str:
    """Mint a throwaway self-signed cert covering ``common_name`` and import it into ACM.

    CreateDomainName rejects endpointConfiguration type PRIVATE with no certificateArn
    even though a PRIVATE domain never resolves it over TLS, so a certificate is a hard
    prerequisite here, not just for edge-optimized/regional domains.
    """
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
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
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    acm = ctx.client("acm")
    resp = acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem)
    cert_arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: _teardown(
        teardown_deadline,
        lambda: acm.delete_certificate(CertificateArn=cert_arn),
        gone=("ResourceNotFoundException",),
        retry=("ResourceInUseException", "ThrottlingException"),
    ))
    return cert_arn


def _provision_private_domain(ctx, apigw, teardown_deadline) -> dict[str, str]:
    """Create a VPC + interface VPC endpoint for execute-api + PRIVATE custom domain name.

    Registers full teardown (LIFO: domain name -> vpc endpoint -> subnet -> vpc).
    """
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-vpce-")

    vpc = ec2.create_vpc(CidrBlock="10.212.0.0/16", TagSpecifications=_tag_spec("vpc", name))
    vpc_id = vpc["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.212.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=_tag_spec("subnet", name),
    )
    subnet_id = subnet["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))

    sg_id = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": ["default"]},
        ]
    )["SecurityGroups"][0]["GroupId"]

    vpce = ec2.create_vpc_endpoint(
        VpcId=vpc_id,
        ServiceName=f"com.amazonaws.{ctx.region}.execute-api",
        VpcEndpointType="Interface",
        SubnetIds=[subnet_id],
        SecurityGroupIds=[sg_id],
        PrivateDnsEnabled=False,
        TagSpecifications=_tag_spec("vpc-endpoint", name),
    )
    vpce_id = vpce["VpcEndpoint"]["VpcEndpointId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc_endpoints(VpcEndpointIds=[vpce_id]))

    def _vpce_state() -> str:
        return ec2.describe_vpc_endpoints(VpcEndpointIds=[vpce_id])["VpcEndpoints"][0]["State"]

    deadline = time.monotonic() + 240
    state = _vpce_state()
    while state not in ("available", "failed") and time.monotonic() < deadline:
        time.sleep(5)
        state = _vpce_state()
    if state != "available":
        raise AssertionError(f"VPC endpoint for execute-api never became available (state={state})")

    domain_name = f"{name}.sim2real.test"
    cert_arn = _import_self_signed_certificate(ctx, domain_name, teardown_deadline)
    policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "execute-api:Invoke",
                    "Resource": "execute-api:/*",
                    "Condition": {"StringEquals": {"aws:SourceVpce": vpce_id}},
                }
            ],
        }
    )
    created = apigw.create_domain_name(
        domainName=domain_name,
        certificateArn=cert_arn,
        endpointConfiguration={"types": ["PRIVATE"], "vpcEndpointIds": [vpce_id]},
        policy=policy,
    )
    domain_name_id = created["domainNameId"]
    domain_name_arn = created["domainNameArn"]
    ctx.on_cleanup(
        lambda: apigw.delete_domain_name(domainName=domain_name, domainNameId=domain_name_id)
    )

    def _domain_status() -> str:
        return apigw.get_domain_name(domainName=domain_name, domainNameId=domain_name_id)[
            "domainNameStatus"
        ]

    deadline = time.monotonic() + 120
    status = _domain_status()
    while status not in ("AVAILABLE", "FAILED") and time.monotonic() < deadline:
        time.sleep(3)
        status = _domain_status()
    if status != "AVAILABLE":
        raise AssertionError(f"private domain name never became AVAILABLE (status={status})")

    return {
        "domain_name": domain_name,
        "domain_name_id": domain_name_id,
        "domain_name_arn": domain_name_arn,
        "vpce_id": vpce_id,
        "vpc_id": vpc_id,
        "subnet_id": subnet_id,
    }


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes ASYNCHRONOUSLY: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation -- and swallowing that would leak
# the VPC while the check passes. So wait (bounded) for the resource's ENIs to go, retry
# DependencyViolation inside the same window, and raise a final failure naming the ENIs still
# attached. Every other error propagates.
# Teardown-only: nothing run() executes calls this, so it cannot change the verdict. The window is
# shared by all of one check's network deletes and fits the suite's 900s cleanup budget here.
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
