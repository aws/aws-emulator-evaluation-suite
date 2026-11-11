"""domain-name-access-association-lifecycle."""
from __future__ import annotations

import json
import subprocess
import tempfile
import time
from pathlib import Path

from behavioral_harness import tags
from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

CHECK = "domain-name-access-association-lifecycle"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDomainNameAccessAssociation -> GetDomainNameAccessAssociations -> Delete removes it."""
    apigw = ctx.client("apigateway")
    domain = _apigw_test_domain(ctx, "assoc")
    cert_arn = _acm_import_cert(ctx, domain)
    vpce = _create_execute_api_vpc_endpoint(ctx)

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
    created_domain = apigw.create_domain_name(
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
    assert created_assoc["accessAssociationSource"] == vpce["vpce_id"], (
        f"expected accessAssociationSource={vpce['vpce_id']}, "
        f"got {created_assoc['accessAssociationSource']}"
    )
    assert created_assoc["accessAssociationSourceType"] == "VPCE", (
        f"expected accessAssociationSourceType=VPCE, got {created_assoc['accessAssociationSourceType']}"
    )

    listed = _list_self_associations(apigw)
    matches = [a for a in listed if a.get("domainNameAccessAssociationArn") == assoc_arn]
    assert len(matches) == 1, listed

    apigw.delete_domain_name_access_association(domainNameAccessAssociationArn=assoc_arn)

    listed_after = _list_self_associations(apigw)
    remaining = [a for a in listed_after if a.get("domainNameAccessAssociationArn") == assoc_arn]
    assert remaining == [], remaining


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
    ctx.on_cleanup(lambda: _delete_cert(acm, arn))
    return arn


# ACM releases a domain name's reference to its certificate asynchronously, so a delete issued
# right after the domain is gone can still see ResourceInUseException; bounded retry waits it out.
def _delete_cert(acm, arn: str, *, timeout_s: float = 300.0, interval_s: float = 10.0) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            acm.delete_certificate(CertificateArn=arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            return result
        time.sleep(interval_s)
        result = probe()
    return result


def _create_execute_api_vpc_endpoint(ctx) -> dict:
    ec2 = ctx.client("ec2")
    tag = ctx.unique_name("sim2real-apigw-vpce-")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.221.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": tag}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.221.1.0/24",
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": tag}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))

    sg_id = ec2.create_security_group(
        GroupName=tag, Description="sim2real apigw vpc endpoint sg", VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": tag}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))

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
        raise AssertionError(
            f"VPC endpoint did not become available (state={state})"
        )
    return {"vpc_id": vpc_id, "subnet_id": subnet_id, "sg_id": sg_id, "vpce_id": vpce_id}


def _vpce_items(ec2, vpce_id: str) -> list[dict]:
    try:
        return ec2.describe_vpc_endpoints(VpcEndpointIds=[vpce_id]).get("VpcEndpoints", [])
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "InvalidVpcEndpointId.NotFound":
            return []
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
