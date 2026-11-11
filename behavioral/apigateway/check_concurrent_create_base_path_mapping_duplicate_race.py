"""concurrent-create-base-path-mapping-duplicate-race."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "concurrent-create-base-path-mapping-duplicate-race"
GROUP = "concurrency"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent CreateBasePathMapping calls for one private domain+basePath: one succeeds, the
    other gets ConflictException, and exactly one mapping persists until deleted (then NotFound)."""
    apigw = ctx.client("apigateway")
    domain = _provision_private_domain(ctx, apigw)
    api_id, stage_name = _provision_deployed_api(ctx, apigw, domain["vpce_id"])

    base_path = "race"

    def _attempt(_: int) -> tuple[str, str]:
        try:
            resp = apigw.create_base_path_mapping(
                domainName=domain["domain_name"],
                domainNameId=domain["domain_name_id"],
                restApiId=api_id,
                basePath=base_path,
                stage=stage_name,
            )
            return ("ok", resp["basePath"])
        except _client_error_type() as exc:
            return ("err", exc.response["Error"]["Code"], exc.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(_attempt, range(2)))

    oks = [r for r in results if r[0] == "ok"]
    errs = [r for r in results if r[0] == "err"]
    assert len(oks) == 1, f"expected exactly one CreateBasePathMapping winner, got {results}"
    assert len(errs) == 1, f"expected exactly one rejected racer, got {results}"
    # The message varies: the losing racer reads "Unable to complete operation due to concurrent
    # modification. Please try again later." when the calls overlap and "Base path already exists
    # for this domain name" when the winner commits first, so only the code is graded here.
    assert errs[0][1] == "ConflictException", (
        f"losing racer did not get ConflictException, got {errs[0][1]}"
    )

    mappings = apigw.get_base_path_mappings(
        domainName=domain["domain_name"], domainNameId=domain["domain_name_id"]
    )["items"]
    matching = [m for m in mappings if m["basePath"] == base_path]
    assert len(matching) == 1, f"expected exactly one persisted mapping, found {matching}"
    assert matching[0]["restApiId"] == api_id
    assert matching[0]["stage"] == stage_name

    apigw.delete_base_path_mapping(
        domainName=domain["domain_name"], domainNameId=domain["domain_name_id"], basePath=base_path
    )
    try:
        still_there = apigw.get_base_path_mapping(
            domainName=domain["domain_name"], domainNameId=domain["domain_name_id"], basePath=base_path
        )
        raise AssertionError(f"deleted base path mapping is still readable: {still_there}")
    except _client_error_type() as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
        assert code == "NotFoundException", f"expected NotFoundException after delete, got {code}"
        assert message == "Invalid base path mapping identifier specified", (
            f"unexpected message {message!r}"
        )


def _client_error_type():
    from botocore.exceptions import ClientError

    return ClientError


def _tag_spec(resource_type: str, name: str) -> list[dict[str, Any]]:
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}]


def _provision_private_domain(ctx, apigw) -> dict[str, str]:
    """Create a VPC + interface VPC endpoint for execute-api + PRIVATE custom domain name.

    Registers full teardown (LIFO: domain name -> vpc endpoint -> subnet -> vpc).
    """
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-vpce-")

    vpc = ec2.create_vpc(CidrBlock="10.213.0.0/16", TagSpecifications=_tag_spec("vpc", name))
    vpc_id = vpc["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.213.1.0/24",
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
    # A PRIVATE custom domain name requires a certificate; a self-signed one imported into ACM
    # needs no domain-ownership validation.
    cert_arn = _import_self_signed_cert(ctx, domain_name)
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


def _import_self_signed_cert(ctx, common_name: str) -> str:
    """Import a two-day self-signed certificate for common_name into ACM (cleanup registered)."""
    import subprocess
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        key_path, cert_path = Path(tmp) / "key.pem", Path(tmp) / "cert.pem"
        require_tools("openssl")
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-days", "2", "-nodes",
             "-keyout", str(key_path), "-out", str(cert_path), "-subj", f"/CN={common_name}",
             "-addext", f"subjectAltName=DNS:{common_name}"],
            capture_output=True, check=True, timeout=30,
        )
        cert_pem, key_pem = cert_path.read_bytes(), key_path.read_bytes()
    acm = ctx.client("acm")
    arn = acm.import_certificate(
        Certificate=cert_pem, PrivateKey=key_pem, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_cert_when_released(acm, arn))
    return arn


def _delete_cert_when_released(acm, arn: str, *, timeout_s: float = 240.0) -> None:
    """DeleteCertificate, waiting out ResourceInUseException while ACM still sees the just-deleted
    domain name as a user of the certificate; any other error, or a cert still in use at the
    deadline, propagates so a leaked certificate fails the cleanup instead of passing silently."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            acm.delete_certificate(CertificateArn=arn)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(10)


def _provision_deployed_api(ctx, apigw, vpce_id: str) -> tuple[str, str]:
    """Create a PRIVATE RestApi (only a private API maps onto a private custom domain name),
    invokable from the VPC endpoint, with a mock-integrated GET / deployed to a stage."""
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
        tags={"sim2real": CHECK},
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


# Async-deleted resources (load balancers, endpoints, ...) leave ENIs behind for a while, so a
# network delete waits (bounded) for them and retries DependencyViolation, then raises naming the
# ENIs still attached. The window is shared by all of one check's network deletes.
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
