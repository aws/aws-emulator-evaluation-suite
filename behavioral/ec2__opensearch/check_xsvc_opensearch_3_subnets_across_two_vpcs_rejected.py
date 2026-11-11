"""xsvc-opensearch-3-subnets-across-two-vpcs-rejected."""
from __future__ import annotations

import random
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "xsvc-opensearch-3-subnets-across-two-vpcs-rejected"
GROUP = 'vpc-placement-rejected'
SERVICES = ['ec2', 'opensearch']

_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")
ENGINE_VERSION = "OpenSearch_2.11"
EBS_OPTIONS = {"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10}
# Two subnets in two AZs means a zone-aware, two-node cluster; that is the only shape for which
# a second subnet is legal at all, so the request is valid in every respect but the VPC split.
ZONE_AWARE_CLUSTER = {"InstanceType": "t3.small.search", "InstanceCount": 2,
                      "ZoneAwarenessEnabled": True,
                      "ZoneAwarenessConfig": {"AvailabilityZoneCount": 2}}


def _ensure_opensearch_slr(ctx) -> None:
    """A VPC domain needs OpenSearch's service-linked role. Create it if absent; it is an
    account-wide singleton other runs depend on, so it is deliberately never deleted."""
    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(AWSServiceName="opensearchservice.amazonaws.com")
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if not (err.get("Code") == "InvalidInput" and "has been taken" in (err.get("Message") or "")):
            raise


def _tags(kind: str, name: str) -> list:
    return [{"ResourceType": kind, "Tags": [{"Key": "Name", "Value": name},
                                            {"Key": "sim2real", "Value": CHECK}]}]


def _retry_delete(label: str, fn, budget_s: float = 10) -> None:
    """Brief DependencyViolation retry only: the engine bounds the whole cleanup chain at 60s,
    so the slow part (domain deletion, ENI release) happens in the check body."""
    deadline = time.monotonic() + budget_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code.endswith(".NotFound"):
                return
            if code != "DependencyViolation" or time.monotonic() > deadline:
                raise RuntimeError(f"{label}: {code}: {exc}") from exc
            time.sleep(2)


def _delete_domain_quiet(osc, domain: str) -> None:
    """Failure-path net: one DeleteDomain call, within the 60s cleanup budget."""
    try:
        osc.delete_domain(DomainName=domain)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise RuntimeError(f"opensearch domain {domain}: {exc}") from exc


def _vpc_domain_enis(ec2, vpc_id: str, domain: str) -> list:
    return ec2.describe_network_interfaces(Filters=[
        {"Name": "vpc-id", "Values": [vpc_id]},
        {"Name": "description", "Values": [f"ES {domain}"]}])["NetworkInterfaces"]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _delete_domain_and_wait(ctx, ec2, osc, domain: str, vpc_id: str,
                            timeout_s: float = 1200) -> None:
    """In-body teardown of the positive-control domain: delete it, wait until it and its ENIs in
    our VPC are gone, so the fast EC2 deletes in cleanup can succeed."""
    osc.delete_domain(DomainName=domain)
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            osc.describe_domain(DomainName=domain)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                break
            raise
        if time.monotonic() >= deadline and _budget_spent(ctx):
            raise TimeoutError(f"domain {domain} gone after DeleteDomain: the run budget ended first; "
                               f"not graded")
        assert time.monotonic() < deadline, f"domain {domain} still present {timeout_s}s after delete"
        time.sleep(2)
    eni_timeout_s = _budget_s(ctx, 900)
    deadline = time.monotonic() + eni_timeout_s
    remaining = _vpc_domain_enis(ec2, vpc_id, domain)
    while remaining and time.monotonic() < deadline:
        time.sleep(2)
        remaining = _vpc_domain_enis(ec2, vpc_id, domain)
    if remaining and _budget_spent(ctx):
        raise TimeoutError(f"the ENIs of deleted domain {domain} released: the run budget ended first; "
                           f"not graded")
    assert remaining == [], (
        f"ENIs {[e['NetworkInterfaceId'] for e in remaining]!r} of deleted domain {domain!r} "
        f"not released within {eni_timeout_s:.0f}s"
    )


class _Accepted(Exception):
    def __init__(self, response):
        super().__init__("call unexpectedly succeeded")
        self.response = response


def _call(fn):
    """(code, message, http_status) of the ClientError fn raises; _Accepted if it succeeds."""
    for attempt in range(12):
        try:
            resp = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") in _THROTTLE_CODES:
                time.sleep(6.0 * (1 + attempt) + random.uniform(0, 6.0))
                continue
            return (err.get("Code"), err.get("Message"),
                    exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"))
        raise _Accepted(resp)
    raise AssertionError("still throttled after 12 attempts")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:e2e", "plane:control")
def run(ctx) -> None:
    """CreateDomain with subnets in two different VPCs is rejected ValidationException and creates
    nothing; the same request with both subnets in one VPC is accepted.

    Reference: https://docs.aws.amazon.com/opensearch-service/latest/developerguide/vpc.html
    """
    ec2 = ctx.client("ec2")
    osc = ctx.client("opensearch")
    domain = ctx.unique_name("sim2real-xv2-")[:28].rstrip("-")
    _ensure_opensearch_slr(ctx)

    azs = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]},
                 {"Name": "zone-type", "Values": ["availability-zone"]}])["AvailabilityZones"])
    assert len(azs) >= 2, f"need two available AZs, region offers {azs!r}"
    o1 = random.randint(64, 156)
    o2 = o1 + random.randint(1, 90)

    vpc_a = ec2.create_vpc(CidrBlock=f"10.{o1}.0.0/16",
                           TagSpecifications=_tags("vpc", f"sim2real-xsvc-{domain}-a"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(f"vpc {vpc_a}", lambda: ec2.delete_vpc(VpcId=vpc_a)))
    vpc_b = ec2.create_vpc(CidrBlock=f"10.{o2}.0.0/16",
                           TagSpecifications=_tags("vpc", f"sim2real-xsvc-{domain}-b"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(f"vpc {vpc_b}", lambda: ec2.delete_vpc(VpcId=vpc_b)))

    def subnet(vpc: str, cidr: str, az: str) -> str:
        sid = ec2.create_subnet(VpcId=vpc, CidrBlock=cidr, AvailabilityZone=az,
                                TagSpecifications=_tags("subnet", f"sim2real-xsvc-{domain}")
                                )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda: _retry_delete(f"subnet {sid}",
                                             lambda: ec2.delete_subnet(SubnetId=sid)))
        return sid

    a1 = subnet(vpc_a, f"10.{o1}.1.0/24", azs[0])
    b2 = subnet(vpc_b, f"10.{o2}.2.0/24", azs[1])
    a2 = subnet(vpc_a, f"10.{o1}.2.0/24", azs[1])
    sg = ec2.create_security_group(GroupName=f"{domain}-sg", Description="sim2real-xsvc opensearch",
                                   VpcId=vpc_a,
                                   TagSpecifications=_tags("security-group", f"{domain}-sg"))["GroupId"]
    ctx.on_cleanup(lambda: _retry_delete(f"sg {sg}", lambda: ec2.delete_security_group(GroupId=sg)))

    def request(subnets: list) -> dict:
        return dict(DomainName=domain, EngineVersion=ENGINE_VERSION,
                    ClusterConfig=dict(ZONE_AWARE_CLUSTER), EBSOptions=dict(EBS_OPTIONS),
                    VPCOptions={"SubnetIds": subnets, "SecurityGroupIds": [sg]},
                    TagList=[{"Key": "sim2real:managed", "Value": "true"}])

    try:
        code, message, status = _call(lambda: osc.create_domain(**request([a1, b2])))
    except _Accepted as acc:
        ctx.on_cleanup(lambda: _delete_domain_quiet(osc, domain))
        raise AssertionError(
            f"CreateDomain with subnets in {vpc_a!r} and {vpc_b!r} was accepted: "
            f"{acc.response.get('DomainStatus', {}).get('VPCOptions')!r}"
        ) from None
    assert code == "ValidationException", (
        f"subnets across two VPCs raised {code!r} ({message!r}), expected ValidationException"
    )
    assert message == "The subnets must be in the same VPC.", f"rejection message was {message!r}"
    assert status == 400, f"rejection HTTP status was {status!r}, expected 400"

    try:
        miss = _call(lambda: osc.describe_domain(DomainName=domain))
    except _Accepted as acc:
        ctx.on_cleanup(lambda: _delete_domain_quiet(osc, domain))
        raise AssertionError(f"rejected CreateDomain still produced {domain!r}: {acc.response!r}") from None
    assert miss[0] == "ResourceNotFoundException", (
        f"DescribeDomain after the rejection raised {miss!r}, expected ResourceNotFoundException"
    )
    assert miss[1] == f"Domain not found: {domain}", f"DescribeDomain message was {miss[1]!r}"
    for v in (vpc_a, vpc_b):
        stray = ec2.describe_network_interfaces(Filters=[
            {"Name": "vpc-id", "Values": [v]},
            {"Name": "description", "Values": [f"ES {domain}"]}])["NetworkInterfaces"]
        assert stray == [], f"rejected CreateDomain left ENIs in {v!r}: {stray!r}"

    # Positive control: the ONLY change is the second subnet now belongs to the first VPC.
    created = None
    for attempt in range(12):
        try:
            created = osc.create_domain(**request([a1, a2]))["DomainStatus"]
            break
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise AssertionError(
                    f"positive control: same-VPC subnets rejected: {exc.response.get('Error')!r}"
                ) from None
            time.sleep(6.0 * (1 + attempt) + random.uniform(0, 6.0))
    assert created is not None, "positive control: CreateDomain still throttled after 12 attempts"
    ctx.on_cleanup(lambda: _delete_domain_quiet(osc, domain))
    vo = created.get("VPCOptions") or {}
    assert vo.get("VPCId") == vpc_a, f"positive control: VPCOptions.VPCId {vo!r}, expected {vpc_a!r}"
    assert sorted(vo.get("SubnetIds") or []) == sorted([a1, a2]), f"positive control: SubnetIds {vo!r}"
    assert sorted(vo.get("AvailabilityZones") or []) == sorted(azs[:2]), (
        f"positive control: AvailabilityZones {vo.get('AvailabilityZones')!r}, expected {azs[:2]!r}"
    )
    # Tear the control domain down in the body: the engine bounds cleanup at 60s, and the VPC
    # pieces cannot be deleted until OpenSearch has released its ENIs.
    _delete_domain_and_wait(ctx, ec2, osc, domain, vpc_a)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
