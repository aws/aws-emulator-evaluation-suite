"""concurrent-delete-domain-name-access-association-race."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

CHECK = "concurrent-delete-domain-name-access-association-race"
GROUP = "concurrency"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent DeleteDomainNameAccessAssociation calls on one association: each may see
    success within the race window, no other error class or message is admitted, and afterwards the
    association is gone: a sequential re-delete is refused with NotFoundException."""
    apigw = ctx.client("apigateway")
    ec2 = ctx.client("ec2")
    acm = ctx.client("acm")

    domain_name = ctx.unique_name("sim2real-priv-").lower() + ".example.com"
    cert_pem, key_pem = _generate_self_signed_cert(domain_name)
    cert_arn = acm.import_certificate(Certificate=cert_pem, PrivateKey=key_pem)["CertificateArn"]
    ctx.on_cleanup(lambda: _delete_certificate(acm, cert_arn))

    vpc_id, subnet_id, sg_id = _create_vpc_stack(ctx, ec2)
    vpce_id = _create_execute_api_endpoint(ctx, ec2, vpc_id, subnet_id, sg_id)

    dn = apigw.create_domain_name(
        domainName=domain_name,
        certificateArn=cert_arn,
        endpointConfiguration={"types": ["PRIVATE"]},
        policy=_allow_all_policy(),
    )
    domain_name_arn = dn["domainNameArn"]
    domain_name_id = dn["domainNameId"]
    ctx.on_cleanup(lambda: _delete_domain_name(apigw, domain_name, domain_name_id))

    assoc_arn = apigw.create_domain_name_access_association(
        domainNameArn=domain_name_arn,
        accessAssociationSourceType="VPCE",
        accessAssociationSource=vpce_id,
    )["domainNameAccessAssociationArn"]

    def _delete():
        return apigw.delete_domain_name_access_association(domainNameAccessAssociationArn=assoc_arn)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_delete) for _ in range(2)]
        outcomes = []
        for fut in futures:
            try:
                fut.result()
                outcomes.append(("ok", None))
            except ClientError as exc:
                err = exc.response["Error"]
                outcomes.append(("err", (err["Code"], err.get("Message"))))

    successes = [o for o in outcomes if o[0] == "ok"]
    failures = [o for o in outcomes if o[0] == "err"]
    assert len(successes) >= 1, f"expected at least 1 of 2 concurrent deletes to succeed, got {outcomes}"
    expected_not_found = "This private custom domain name doesn't have any domain name access associations."
    unexpected = [err for _, err in failures if err != ("NotFoundException", expected_not_found)]
    assert not unexpected, (
        f"expected any losing delete to fail with NotFoundException {expected_not_found!r}, got {outcomes}"
    )

    remaining = apigw.get_domain_name_access_associations().get("items", [])
    assert all(i["domainNameAccessAssociationArn"] != assoc_arn for i in remaining), (
        "association is still listed after a successful delete"
    )

    err = _redelete_error(_delete)
    assert err["Code"] == "NotFoundException", f"expected a re-delete to 404, got {err}"
    assert err.get("Message") == expected_not_found, f"unexpected re-delete message {err.get('Message')!r}"


# ===== helpers (self-contained) =====


def _delete_domain_name(apigw, domain_name, domain_name_id):
    """Teardown: a PRIVATE domain name is addressed by name AND id; ride out the throttle."""
    for i in range(6):
        try:
            apigw.delete_domain_name(domainName=domain_name, domainNameId=domain_name_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code != "TooManyRequestsException" or i == 5:
                raise
            time.sleep(32)


def _delete_certificate(acm, cert_arn):
    """Teardown: the certificate stays in use until the domain-name deletion settles."""
    deadline = time.monotonic() + 300
    while True:
        try:
            acm.delete_certificate(CertificateArn=cert_arn)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(10)


def _redelete_error(delete, attempts=6, delay_s=32.0):
    """The Error a sequential re-delete raises, waiting out API Gateway's ~1-req/30s control-plane
    throttle; a re-delete that succeeds is itself a failure."""
    for i in range(attempts):
        try:
            result = delete()
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] != "TooManyRequestsException" or i == attempts - 1:
                return err
            time.sleep(delay_s)
        else:
            raise AssertionError(f"a sequential re-delete of the deleted association succeeded: {result!r}")
    raise AssertionError("unreachable")


def _generate_self_signed_cert(common_name: str) -> tuple[bytes, bytes]:
    with tempfile.TemporaryDirectory() as tmp:
        key_path = os.path.join(tmp, "key.pem")
        cert_path = os.path.join(tmp, "cert.pem")
        require_tools("openssl")
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", key_path, "-out", cert_path,
                "-days", "2", "-nodes", "-subj", f"/CN={common_name}",
            ],
            check=True,
            capture_output=True,
            timeout=30,
        )
        with open(cert_path, "rb") as f:
            cert_pem = f.read()
        with open(key_path, "rb") as f:
            key_pem = f.read()
    return cert_pem, key_pem


def _create_vpc_stack(ctx, ec2) -> tuple[str, str, str]:
    tag = ctx.unique_name("sim2real-apigw-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.77.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": tag}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.77.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": tag}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))

    sg_id = ec2.create_security_group(
        GroupName=tag,
        Description="sim2real apigateway domain-name-access-association test",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": tag}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))
    return vpc_id, subnet_id, sg_id


def _create_execute_api_endpoint(ctx, ec2, vpc_id: str, subnet_id: str, sg_id: str) -> str:
    service_name = f"com.amazonaws.{ctx.region}.execute-api"
    tag = ctx.unique_name("sim2real-apigw-vpce-")
    vpce = ec2.create_vpc_endpoint(
        VpcEndpointType="Interface",
        VpcId=vpc_id,
        ServiceName=service_name,
        SubnetIds=[subnet_id],
        SecurityGroupIds=[sg_id],
        PrivateDnsEnabled=False,
        TagSpecifications=[{"ResourceType": "vpc-endpoint", "Tags": [{"Key": "Name", "Value": tag}]}],
    )["VpcEndpoint"]
    vpce_id = vpce["VpcEndpointId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc_endpoints(VpcEndpointIds=[vpce_id]))

    deadline = time.monotonic() + 240
    state = vpce.get("State")
    while state != "available" and time.monotonic() < deadline:
        time.sleep(5)
        state = ec2.describe_vpc_endpoints(VpcEndpointIds=[vpce_id])["VpcEndpoints"][0]["State"]
    if state != "available":
        raise AssertionError(f"VPC endpoint never reached 'available' state (last seen: {state})")
    return vpce_id


def _allow_all_policy() -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "execute-api:Invoke",
                    "Resource": "execute-api:/*",
                }
            ],
        }
    )


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
