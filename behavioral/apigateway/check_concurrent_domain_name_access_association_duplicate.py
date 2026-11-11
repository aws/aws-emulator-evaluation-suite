"""concurrent-domain-name-access-association-duplicate."""
from __future__ import annotations

import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "concurrent-domain-name-access-association-duplicate"
GROUP = "concurrency"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent CreateDomainNameAccessAssociation calls for one private domain and VPC
    endpoint: one is created, the other gets BadRequestException ("...already exists"), and
    exactly one association remains; deleting it makes it gone and a repeat delete fails."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    apigw = ctx.client("apigateway")
    domain_name = ctx.unique_name("sim2real-priv-").lower() + ".example.com"
    cert_arn = _import_self_signed_certificate(ctx, domain_name, teardown_deadline)

    domain = apigw.create_domain_name(
        domainName=domain_name,
        certificateArn=cert_arn,
        endpointConfiguration={"types": ["PRIVATE"]},
        policy=(
            '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*",'
            '"Action":"execute-api:Invoke","Resource":["execute-api:/*"]}]}'
        ),
    )
    domain_name_arn = domain["domainNameArn"]
    # A PRIVATE domain name is assigned a domainNameId, and Get/DeleteDomainName then
    # require it too -- omitting it here would leak the domain on cleanup.
    domain_name_id = domain.get("domainNameId")
    delete_domain_kwargs: dict[str, Any] = {"domainName": domain_name}
    if domain_name_id:
        delete_domain_kwargs["domainNameId"] = domain_name_id
    ctx.on_cleanup(lambda: apigw.delete_domain_name(**delete_domain_kwargs))
    _wait_for_domain_available(apigw, domain_name, domain_name_id)

    vpce_id = _create_execute_api_vpc_endpoint(ctx, teardown_deadline)

    barrier = threading.Barrier(2)
    outcomes: list[dict[str, Any]] = []
    lock = threading.Lock()

    def _associate() -> None:
        barrier.wait(timeout=5)
        try:
            resp = apigw.create_domain_name_access_association(
                domainNameArn=domain_name_arn,
                accessAssociationSourceType="VPCE",
                accessAssociationSource=vpce_id,
            )
            with lock:
                outcomes.append({"ok": True, "arn": resp["domainNameAccessAssociationArn"]})
        except ClientError as err:
            with lock:
                outcomes.append(
                    {
                        "ok": False,
                        "code": _error_code(err),
                        "message": err.response.get("Error", {}).get("Message"),
                    }
                )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_associate) for _ in range(2)]
        for f in futures:
            f.result(timeout=30)

    successes = [o for o in outcomes if o["ok"]]
    failures = [o for o in outcomes if not o["ok"]]

    if len(successes) == 1 and len(failures) == 1:
        ctx.on_cleanup(lambda: _safe_delete_association(apigw, successes[0]["arn"], teardown_deadline))
    elif successes:
        for s in successes:
            ctx.on_cleanup(lambda arn=s["arn"]: _safe_delete_association(apigw, arn, teardown_deadline))

    assert len(successes) == 1, f"expected exactly 1 winner, got {len(successes)}: {outcomes}"
    assert len(failures) == 1, f"expected exactly 1 loser, got {len(failures)}: {outcomes}"
    # AWS rejects the racing duplicate with BadRequestException, not ConflictException.
    assert failures[0]["code"] == "BadRequestException", (
        f"expected BadRequestException for the duplicate association, got "
        f"{failures[0]['code']}: {failures[0].get('message')}"
    )
    loser_message = failures[0].get("message")
    assert loser_message == (
        "The domain name access association between this VPC endpoint and domain name already exists."
    ), (
        f"expected an 'already exists' BadRequestException for the duplicate association, "
        f"got: {failures[0].get('message')!r}"
    )

    associations = apigw.get_domain_name_access_associations(resourceOwner="SELF")["items"]
    matching = [
        a
        for a in associations
        if a["domainNameArn"] == domain_name_arn and a["accessAssociationSource"] == vpce_id
    ]
    assert len(matching) == 1, f"expected exactly 1 access association, found {len(matching)}"

    winner_arn = successes[0]["arn"]
    apigw.delete_domain_name_access_association(domainNameAccessAssociationArn=winner_arn)
    _poll_association_gone(apigw, domain_name_arn, vpce_id)

    code, message = _delete_error(apigw, winner_arn)
    assert code == "NotFoundException", (
        f"expected NotFoundException re-deleting the already-deleted association, got {code}"
    )
    assert message == "This private custom domain name doesn't have any domain name access associations.", message


def _error_code(err: Exception) -> str | None:
    response = getattr(err, "response", None)
    if not response:
        return None
    return response.get("Error", {}).get("Code")


def _safe_delete_association(apigw, arn: str, teardown_deadline) -> None:
    """Teardown for an association this check may already have deleted itself."""
    _teardown(
        teardown_deadline,
        lambda: apigw.delete_domain_name_access_association(domainNameAccessAssociationArn=arn),
        gone=("NotFoundException",),
        retry=("TooManyRequestsException",),
    )


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


def _delete_error(apigw, arn: str) -> tuple[str | None, str | None]:
    """The (code, message) of re-deleting an association; a success is a mismatch."""
    try:
        apigw.delete_domain_name_access_association(domainNameAccessAssociationArn=arn)
    except ClientError as err:
        return _error_code(err), err.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected delete of already-deleted association {arn} to fail, but it succeeded")


def _wait_for_domain_available(
    apigw, domain_name: str, domain_name_id: str | None, timeout_s: float = 120.0, interval_s: float = 3.0
) -> None:
    """A freshly-created PRIVATE domain name is not immediately AVAILABLE; racing
    CreateDomainNameAccessAssociation against it before it settles gets every racer
    rejected with BadRequestException, so the real conflict path is never exercised."""
    kwargs: dict[str, Any] = {"domainName": domain_name}
    if domain_name_id:
        kwargs["domainNameId"] = domain_name_id

    def _status() -> str:
        return apigw.get_domain_name(**kwargs)["domainNameStatus"]

    deadline = time.monotonic() + timeout_s
    status = _status()
    while status not in ("AVAILABLE", "FAILED") and time.monotonic() < deadline:
        time.sleep(interval_s)
        status = _status()
    if status != "AVAILABLE":
        raise AssertionError(f"private domain name never became AVAILABLE (status={status})")


def _poll_association_gone(
    apigw, domain_name_arn: str, vpce_id: str, timeout_s: float = 60.0, interval_s: float = 3.0
) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        items = apigw.get_domain_name_access_associations(resourceOwner="SELF")["items"]
        still = [
            a
            for a in items
            if a["domainNameArn"] == domain_name_arn and a["accessAssociationSource"] == vpce_id
        ]
        if not still:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"deleted access association still listed after {timeout_s}s: {still}")
        time.sleep(interval_s)


def _import_self_signed_certificate(ctx, domain_name: str, teardown_deadline) -> str:
    """Generate a throwaway self-signed cert via openssl and import it into ACM.

    A private custom domain name requires the certificate's CN/SAN to actually
    cover the domain name being created (CreateDomainName rejects certs that
    don't cover the requested domain), so the cert's CN must match domain_name.
    """
    require_tools("openssl")
    acm = ctx.client("acm")
    with tempfile.TemporaryDirectory() as tmp:
        key_path = Path(tmp) / "key.pem"
        cert_path = Path(tmp) / "cert.pem"
        cmd = [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
            "-days",
            "2",
            "-nodes",
            "-subj",
            f"/CN={domain_name}",
        ]
        subprocess.run(cmd, check=True, capture_output=True, timeout=60)
        cert_bytes = cert_path.read_bytes()
        key_bytes = key_path.read_bytes()

    resp = acm.import_certificate(Certificate=cert_bytes, PrivateKey=key_bytes)
    cert_arn = resp["CertificateArn"]
    # The certificate reads as in use until the domain name's deletion propagates.
    ctx.on_cleanup(lambda: _teardown(
        teardown_deadline,
        lambda: acm.delete_certificate(CertificateArn=cert_arn),
        gone=("ResourceNotFoundException",),
        retry=("ResourceInUseException",),
    ))
    return cert_arn


def _create_execute_api_vpc_endpoint(ctx, teardown_deadline) -> str:
    """Stand up a minimal VPC + subnet + security group + interface VPC endpoint for
    execute-api, to use as a real accessAssociationSource.
    """
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-dnaa-")

    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]

    try:
        vpc_id = ec2.create_vpc(
            CidrBlock="10.77.0.0/16",
            TagSpecifications=[_tag_spec("vpc", name)],
        )["Vpc"]["VpcId"]
    except ClientError as exc:
        if _error_code(exc) == "VpcLimitExceeded":
            raise AssertionError(
                "unreachable: account has hit its VPC limit, cannot provision a test VPC"
            )
        raise
    ctx.on_cleanup(lambda: _teardown(
        teardown_deadline,
        lambda: ec2.delete_vpc(VpcId=vpc_id),
        gone=("InvalidVpcID.NotFound",),
        retry=("DependencyViolation",),
    ))

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.77.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=[_tag_spec("subnet", name)],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _teardown(
        teardown_deadline,
        lambda: ec2.delete_subnet(SubnetId=subnet_id),
        gone=("InvalidSubnetID.NotFound",),
        retry=("DependencyViolation",),
    ))

    sg_id = ec2.create_security_group(
        GroupName=name,
        Description="sim2real behavioral check: execute-api VPCE",
        VpcId=vpc_id,
        TagSpecifications=[_tag_spec("security-group", name)],
    )["GroupId"]
    ctx.on_cleanup(lambda: _teardown(
        teardown_deadline,
        lambda: ec2.delete_security_group(GroupId=sg_id),
        gone=("InvalidGroup.NotFound",),
        retry=("DependencyViolation",),
    ))

    region = ctx.region
    vpce_id = ec2.create_vpc_endpoint(
        VpcEndpointType="Interface",
        VpcId=vpc_id,
        ServiceName=f"com.amazonaws.{region}.execute-api",
        SubnetIds=[subnet_id],
        SecurityGroupIds=[sg_id],
        PrivateDnsEnabled=False,
        TagSpecifications=[_tag_spec("vpc-endpoint", name)],
    )["VpcEndpoint"]["VpcEndpointId"]
    ctx.on_cleanup(lambda: _delete_vpc_endpoint_with_wait(ec2, vpce_id, teardown_deadline))

    def _vpce_state() -> str:
        return ec2.describe_vpc_endpoints(VpcEndpointIds=[vpce_id])["VpcEndpoints"][0]["State"]

    deadline = time.monotonic() + 240
    state = _vpce_state()
    while state not in ("available", "failed") and time.monotonic() < deadline:
        time.sleep(5)
        state = _vpce_state()
    if state != "available":
        raise AssertionError(f"VPC endpoint for execute-api never became available (state={state})")

    return vpce_id


def _tag_spec(resource_type: str, name: str) -> dict[str, Any]:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _delete_vpc_endpoint_with_wait(ec2, vpce_id: str, teardown_deadline) -> None:
    """Delete the endpoint and wait until DescribeVpcEndpoints reports it deleted or
    InvalidVpcEndpointId.NotFound, so its network interfaces have released the subnet."""
    deadline = teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_RETRY_S - 120.0)
    failed = ec2.delete_vpc_endpoints(VpcEndpointIds=[vpce_id]).get("Unsuccessful", [])
    failed = [f for f in failed if f.get("Error", {}).get("Code") != "InvalidVpcEndpointId.NotFound"]
    assert not failed, f"DeleteVpcEndpoints refused {vpce_id}: {failed}"
    state = None
    while True:
        try:
            endpoints = ec2.describe_vpc_endpoints(VpcEndpointIds=[vpce_id]).get("VpcEndpoints", [])
        except ClientError as err:
            if _error_code(err) != "InvalidVpcEndpointId.NotFound":
                raise
            return
        state = endpoints[0]["State"] if endpoints else "deleted"
        if state.lower() == "deleted":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"VPC endpoint {vpce_id} not deleted by the teardown deadline (state={state})")
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
