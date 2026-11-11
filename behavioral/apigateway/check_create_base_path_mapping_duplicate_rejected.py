"""create-base-path-mapping-duplicate-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "create-base-path-mapping-duplicate-rejected"
GROUP = "concurrency"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Remapping an already-mapped domain+basePath fails with ConflictException.

    The original mapping is unchanged and a different basePath on the same domain still maps.
    """
    apigw = ctx.client("apigateway")
    domain = _provision_private_domain(ctx, apigw)
    api_id_1, stage_1 = _provision_deployed_api(ctx, apigw, domain["vpce_id"])
    api_id_2, stage_2 = _provision_deployed_api(ctx, apigw, domain["vpce_id"])

    base_path = "dup"
    apigw.create_base_path_mapping(
        domainName=domain["domain_name"],
        domainNameId=domain["domain_name_id"],
        restApiId=api_id_1,
        basePath=base_path,
        stage=stage_1,
    )
    ctx.on_cleanup(
        lambda: apigw.delete_base_path_mapping(
            domainName=domain["domain_name"], domainNameId=domain["domain_name_id"], basePath=base_path
        )
    )

    code, message = _error(
        lambda: apigw.create_base_path_mapping(
            domainName=domain["domain_name"],
            domainNameId=domain["domain_name_id"],
            restApiId=api_id_2,
            basePath=base_path,
            stage=stage_2,
        )
    )
    assert code == "ConflictException", f"duplicate basePath mapping was not rejected: {code}"
    assert message == "Base path already exists for this domain name", f"unexpected ConflictException message {message!r}"

    # Effect absent: the original mapping is unchanged, still pointing at api_id_1/stage_1.
    unchanged = apigw.get_base_path_mapping(
        domainName=domain["domain_name"], domainNameId=domain["domain_name_id"], basePath=base_path
    )
    assert unchanged["restApiId"] == api_id_1, "rejected remap mutated the mapping's restApiId"
    assert unchanged["stage"] == stage_1, "rejected remap mutated the mapping's stage"

    # Positive control: a different basePath on the same domain still succeeds.
    control_path = "dup2"
    control = apigw.create_base_path_mapping(
        domainName=domain["domain_name"],
        domainNameId=domain["domain_name_id"],
        restApiId=api_id_2,
        basePath=control_path,
        stage=stage_2,
    )
    ctx.on_cleanup(
        lambda: apigw.delete_base_path_mapping(
            domainName=domain["domain_name"], domainNameId=domain["domain_name_id"], basePath=control_path
        )
    )
    assert control["basePath"] == control_path, (
        f"control mapping response basePath mismatch: expected {control_path!r}, got {control!r}"
    )
    assert control["restApiId"] == api_id_2, (
        f"control mapping response restApiId mismatch: expected {api_id_2!r}, got {control!r}"
    )

    # Terminal read: an independent GetBasePathMapping, not the mutating call's own response --
    # proves the control mapping was actually persisted, not just echoed back.
    persisted = apigw.get_base_path_mapping(
        domainName=domain["domain_name"], domainNameId=domain["domain_name_id"], basePath=control_path
    )
    assert persisted["restApiId"] == api_id_2, (
        f"control mapping not persisted: expected restApiId={api_id_2!r}, got {persisted!r}"
    )
    assert persisted["stage"] == stage_2, (
        f"control mapping not persisted: expected stage={stage_2!r}, got {persisted!r}"
    )


def _error(fn):
    """Call fn(); return (code, message) of the refusal. A call that succeeds fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _tag_spec(resource_type: str, name: str) -> list[dict[str, Any]]:
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}]


def _self_signed_cert_arn(ctx, acm, common_name: str) -> str:
    """Mint a self-signed cert and import it into ACM; import_certificate performs no
    domain-ownership/DNS validation, so this does not require owning a real domain."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    resp = acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem)
    cert_arn = resp["CertificateArn"]
    ctx.on_cleanup(lambda: acm.delete_certificate(CertificateArn=cert_arn))
    return cert_arn


def _provision_private_domain(ctx, apigw) -> dict[str, str]:
    """Create a VPC + interface VPC endpoint for execute-api, a self-signed ACM certificate
    (real AWS rejects CreateDomainName for endpointConfiguration.types=PRIVATE with
    BadRequestException "A certificate was not provided for the endpoint type PRIVATE" unless
    certificateArn is set), and the PRIVATE custom domain name itself.

    Registers full teardown (LIFO: domain name -> certificate -> vpc endpoint -> subnet -> vpc).
    """
    ec2 = ctx.client("ec2")
    acm = ctx.client("acm")
    name = ctx.unique_name("sim2real-behav-vpce-")

    vpc = ec2.create_vpc(CidrBlock="10.214.0.0/16", TagSpecifications=_tag_spec("vpc", name))
    vpc_id = vpc["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.214.1.0/24",
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
    cert_arn = _self_signed_cert_arn(ctx, acm, domain_name)
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


def _provision_deployed_api(ctx, apigw, vpce_id: str) -> tuple[str, str]:
    """Create a mock-integrated GET / RestApi and deploy it to a stage.

    Must be endpointConfiguration.types=PRIVATE: real AWS rejects CreateBasePathMapping with
    BadRequestException "REGIONAL/EDGE API is not supported for PRIVATE custom domain name" when
    mapping a REGIONAL/EDGE RestApi under a PRIVATE domain name.
    """
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
    api = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-"),
        endpointConfiguration={"types": ["PRIVATE"], "vpcEndpointIds": [vpce_id]},
        policy=policy,
    )
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )
    stage_name = "prod"
    apigw.create_deployment(restApiId=api_id, stageName=stage_name)
    return api_id, stage_name


# AWS-managed ENIs (endpoints, load balancers, functions) leave a VPC asynchronously after their
# owner's delete returns, so DeleteSubnet/DeleteSecurityGroup/DeleteVpc can fail with
# DependencyViolation. Wait (bounded) for the ENIs to go, retry inside the same window, and raise
# naming any ENIs still attached. Teardown-only: run() never calls this.
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
