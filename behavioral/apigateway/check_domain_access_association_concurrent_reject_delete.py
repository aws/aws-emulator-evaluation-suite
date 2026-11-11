"""domain-access-association-concurrent-reject-delete."""
from __future__ import annotations

import subprocess
import tempfile
import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "domain-access-association-concurrent-reject-delete"
GROUP = 'concurrency'
SERVICES = ['apigateway']


_TEARDOWN_RETRY_S = 300.0
_TEARDOWN_RETRY_CODES = (
    "TooManyRequestsException", "ThrottlingException", "ConflictException", "ResourceInUseException",
    "RequestLimitExceeded",
)
_VPCE_GONE = ("InvalidVpcEndpointId.NotFound", "InvalidVpcEndpoint.NotFound")


def _ignore(fn, *gone):
    """Teardown: done when fn succeeds or answers a `gone` code; retry throttling and in-use
    refusals every 2 s for a bounded window, and raise everything else."""
    deadline = time.monotonic() + _TEARDOWN_RETRY_S
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in gone:
                return
            if code not in _TEARDOWN_RETRY_CODES or time.monotonic() >= deadline:
                raise
        time.sleep(2)

def _import_self_signed_certificate(ctx, common_name):
    """Generate an ephemeral self-signed cert with openssl and import it into ACM.
    Returns the CertificateArn (teardown registered)."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")
    with tempfile.TemporaryDirectory() as d:
        key_path = f"{d}/key.pem"
        cert_path = f"{d}/cert.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-keyout", key_path,
             "-out", cert_path, "-days", "2", "-subj", f"/CN={common_name}"],
            check=True, capture_output=True, timeout=30,
        )
        with open(cert_path) as f:
            cert_pem = f.read()
        with open(key_path) as f:
            key_pem = f.read()
    acm = ctx.client("acm")
    arn = acm.import_certificate(
        Certificate=cert_pem.encode("utf-8"), PrivateKey=key_pem.encode("utf-8")
    )["CertificateArn"]
    ctx.on_cleanup(lambda: _ignore(lambda: acm.delete_certificate(CertificateArn=arn), "ResourceNotFoundException"))
    return arn

def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, ctx=None):
    import time
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"the polled condition (last={result!r}): the run budget ended first; not graded")
            raise AssertionError(f"condition not met within {timeout_s}s (last={result!r})")
        time.sleep(interval_s)
        result = probe()
    return result

def _create_execute_api_vpc_endpoint(ctx):
    """Create an `execute-api` Interface VPC endpoint in a fresh VPC (an account may have no
    default VPC); CreateDomainNameAccessAssociation requires a real endpoint id as its source.
    Returns the VpcEndpointId (teardown registered)."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-vpce-")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.231.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _ignore(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id), "InvalidVpcID.NotFound"))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.231.1.0/24",
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _ignore(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id), "InvalidSubnetID.NotFound"))

    sg_id = ec2.create_security_group(
        GroupName=name, Description="sim2real apigw vpc endpoint sg", VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _ignore(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id), "InvalidGroup.NotFound"))

    endpoint = ec2.create_vpc_endpoint(
        VpcId=vpc_id,
        ServiceName=f"com.amazonaws.{ctx.region}.execute-api",
        VpcEndpointType="Interface",
        SubnetIds=[subnet_id],
        SecurityGroupIds=[sg_id],
        PrivateDnsEnabled=False,
        TagSpecifications=[{"ResourceType": "vpc-endpoint", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    vpce_id = endpoint["VpcEndpoint"]["VpcEndpointId"]

    def _cleanup_vpce():
        # DeleteVpcEndpoints reports per-endpoint failures in Unsuccessful, not as an error.
        failed = ec2.delete_vpc_endpoints(VpcEndpointIds=[vpce_id]).get("Unsuccessful", [])
        if any(f["Error"]["Code"] not in _VPCE_GONE for f in failed):
            raise RuntimeError(f"DeleteVpcEndpoints({vpce_id}) failed: {failed!r}")
        _poll_until(lambda: _vpce_state(ec2, vpce_id), lambda st: st in (None, "deleted"),
                    timeout_s=300, interval_s=2)
    ctx.on_cleanup(_cleanup_vpce)

    state = _poll_until(
        lambda: ec2.describe_vpc_endpoints(VpcEndpointIds=[vpce_id])["VpcEndpoints"][0]["State"],
        lambda s: s in ("available", "failed"),
        timeout_s=_budget_s(ctx, 300.0), interval_s=2, ctx=ctx,
    )
    if state != "available":
        raise AssertionError(f"execute-api VPC endpoint did not become available (state={state})")
    return vpce_id

def _vpce_state(ec2, vpce_id):
    """The endpoint's State, or None when DescribeVpcEndpoints does not know it."""
    try:
        items = ec2.describe_vpc_endpoints(VpcEndpointIds=[vpce_id]).get("VpcEndpoints", [])
    except ClientError as exc:
        if exc.response["Error"]["Code"] in _VPCE_GONE:
            return None
        raise
    return items[0]["State"] if items else None


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; a success is a defect."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _run_concurrent(fns, *, timeout_s=60):
    import concurrent.futures
    results = [None] * len(fns)
    resolved = set()

    def _capture(fut, idx):
        try:
            results[idx] = fut.result()
        except Exception as exc:
            results[idx] = exc
        resolved.add(idx)
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns)))
    try:
        future_to_idx = {ex.submit(fn): i for i, fn in enumerate(fns)}
        try:
            for fut in concurrent.futures.as_completed(future_to_idx, timeout=timeout_s):
                _capture(fut, future_to_idx[fut])
        except concurrent.futures.TimeoutError as timeout_exc:
            for fut, idx in future_to_idx.items():
                if idx in resolved:
                    continue
                if fut.done():
                    _capture(fut, idx)
                else:
                    fut.cancel()
                    results[idx] = timeout_exc
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return results


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Racing Reject against Delete on a same-account access association: Delete succeeds, Reject
    fails (BadRequest same-account, or NotFound if Delete won), and the association is gone after.
    Reject only applies to a source owned by another account, so it can never succeed here."""
    ag = ctx.client("apigateway")
    domain = f"{ctx.unique_name('sim2real-behav-privdom-')}.example.com"
    cert_arn = _import_self_signed_certificate(ctx, domain)
    created_domain = ag.create_domain_name(
        domainName=domain,
        certificateArn=cert_arn,
        endpointConfiguration={"types": ["PRIVATE"]},
    )
    domain_arn = created_domain["domainNameArn"]
    domain_id = created_domain["domainNameId"]
    ctx.on_cleanup(lambda: _ignore(lambda: ag.delete_domain_name(domainName=domain, domainNameId=domain_id), "NotFoundException"))

    vpce_id = _create_execute_api_vpc_endpoint(ctx)

    assoc = ag.create_domain_name_access_association(
        domainNameArn=domain_arn,
        accessAssociationSourceType="VPCE",
        accessAssociationSource=vpce_id,
    )
    assoc_arn = assoc["domainNameAccessAssociationArn"]
    ctx.on_cleanup(lambda: _ignore(
        lambda: ag.delete_domain_name_access_association(domainNameAccessAssociationArn=assoc_arn),
        "NotFoundException",
    ))

    def _reject():
        return ag.reject_domain_name_access_association(
            domainNameAccessAssociationArn=assoc_arn, domainNameArn=domain_arn
        )

    def _delete():
        return ag.delete_domain_name_access_association(
            domainNameAccessAssociationArn=assoc_arn
        )

    same_account = (
        "BadRequestException",
        "Cannot reject the domain name access association when the private custom domain "
        "and domain name access association are in the same account.",
    )
    no_associations = (
        "NotFoundException",
        "This private custom domain name doesn't have any domain name access associations.",
    )

    # Each refusal message is graded on its own, so the race below decides neither verdict.
    pre_reject_err = _error(_reject)
    assert pre_reject_err == same_account, (
        f"rejecting a live same-account association must fail with {same_account!r}, got "
        f"{pre_reject_err!r}"
    )

    reject_result, delete_result = _run_concurrent([_reject, _delete])

    assert not isinstance(delete_result, BaseException), (
        f"expected DeleteDomainNameAccessAssociation to succeed (it is the only "
        f"legitimate mutation contending here), got {delete_result!r}"
    )

    assert isinstance(reject_result, ClientError), (
        "expected RejectDomainNameAccessAssociation to be rejected (a same-account "
        "source can never legitimately be rejected), but it succeeded"
    )
    reject_err = (reject_result.response["Error"]["Code"], reject_result.response["Error"].get("Message"))
    assert reject_err in (same_account, no_associations), (
        f"expected {same_account!r} (same-account source) or {no_associations!r} "
        f"(already removed by the concurrent Delete winner), got {reject_err!r}"
    )

    assocs_after = ag.get_domain_name_access_associations()["items"]
    assert not any(a["domainNameAccessAssociationArn"] == assoc_arn for a in assocs_after), (
        "association must be gone (single consistent terminal state) after the race - "
        "Reject must never have left it half-applied"
    )

    post_reject_err = _error(_reject)
    assert post_reject_err == no_associations, (
        f"rejecting the association after Delete removed it must fail with "
        f"{no_associations!r}, got {post_reject_err!r}"
    )

    try:
        result = ag.delete_domain_name_access_association(domainNameAccessAssociationArn=assoc_arn)
    except ClientError as exc:
        second_delete_err = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
    else:
        raise AssertionError(f"a further delete of the dead association SUCCEEDED: {result!r}")
    assert second_delete_err == no_associations, (
        f"the association id must be dead, not just unlisted: expected a further delete on it "
        f"to fail with {no_associations!r}, got {second_delete_err!r}"
    )


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
        _time.sleep(2)
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
        _time.sleep(2)


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
