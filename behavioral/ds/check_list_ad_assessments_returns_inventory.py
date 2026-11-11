"""list-ad-assessments-returns-inventory."""

from __future__ import annotations

import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-ad-assessments-returns-inventory"
GROUP = 'lifecycle'
SERVICES = ['ds']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A directory assessment this check starts appears in the account's ListADAssessments
    inventory and in an independent DescribeADAssessment, then disappears from both once
    deleted."""
    ds = ctx.client("ds")
    ec2 = ctx.client("ec2")

    vpc_id, subnet_ids, owns_vpc = _get_or_create_vpc_and_subnet(ctx, ec2)
    if owns_vpc:
        ctx.on_cleanup(lambda: _teardown_vpc(ec2, vpc_id, subnet_ids))

    dns_name = f"{ctx.unique_name('sim2real-adassess').rstrip('-')}.example.com"
    resp = ds.start_ad_assessment(
        AssessmentConfiguration={
            "CustomerDnsIps": ["10.24.34.10", "10.24.34.11"],
            "DnsName": dns_name,
            "VpcSettings": {"VpcId": vpc_id, "SubnetIds": subnet_ids},
            "InstanceIds": ["i-0123456789abcdef0", "i-0fedcba987654321f"],
        }
    )
    assessment_id = resp["AssessmentId"]
    ctx.on_cleanup(lambda: _safe(lambda: ds.delete_ad_assessment(AssessmentId=assessment_id), "EntityDoesNotExistException"))

    # Independent read #1: the started assessment is visible in the account's inventory --
    # the thing this check exists to prove. list_ad_assessments is a different operation than
    # the one that started it, and the assertion is containment, not a bare count or isinstance,
    # so a target that ignores the account's real inventory (e.g. always returns []) fails it.
    listed = _list_ids(ds)
    assert assessment_id in listed, (assessment_id, listed)

    # Independent read #2, a third operation: describe agrees on identity and configuration.
    described = ds.describe_ad_assessment(AssessmentId=assessment_id)["Assessment"]
    assert described["AssessmentId"] == assessment_id, described
    assert described["DnsName"] == dns_name, described

    # Delete proves gone: an independent read no longer lists it, and describing the dead id
    # fails with the specific not-found error (AWS allows deleting an in-progress assessment).
    ds.delete_ad_assessment(AssessmentId=assessment_id)
    remaining = _list_ids(ds)
    assert assessment_id not in remaining, (assessment_id, remaining)
    code, message, request_id = _client_error(
        lambda: ds.describe_ad_assessment(AssessmentId=assessment_id)
    )
    assert code == "EntityDoesNotExistException", code
    expected = f"Assessment Id {assessment_id} does not exist. : RequestId: {request_id}"
    assert message == expected, (
        f"DescribeADAssessment of the deleted assessment must refuse with {expected!r}, "
        f"got {message!r}"
    )


# ===== helpers =====

def _list_ids(ds):
    ids = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = ds.list_ad_assessments(**kwargs)
        ids.extend(a["AssessmentId"] for a in resp.get("Assessments", []))
        token = resp.get("NextToken")
        if not token:
            return ids


def _client_error(fn):
    """Call fn(); return (Error.Code, Error.Message, RequestId) of the ClientError it must raise.
    An unexpected SUCCESS raises rather than passing as a code mismatch. ds echoes the
    refused call's RequestId in its message, so the caller needs it to build the exact text."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        request_id = (exc.response.get("ResponseMetadata") or {}).get("RequestId")
        return err.get("Code"), err.get("Message") or "", request_id
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe(fn, not_found: str, timeout_s: float = 500.0) -> None:
    """Run a teardown call; done when it succeeds or answers `not_found`. DependencyViolation
    (ENIs still being released) is retried every 2 s to the deadline; anything else raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == not_found:
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _get_or_create_vpc_and_subnet(ctx, ec2):
    """AssessmentConfiguration needs a real VPC and two subnets in different AZs to reference
    (real AWS rejects anything else with InvalidParameterException -- undocumented in the
    model), and the per-region VPC quota is small. So
    this adopts an existing VPC that already spans two AZs -- the VPC and its subnets are only
    ever referenced, never mutated -- and only creates its own VPC as a last resort when the
    account genuinely has none that qualify."""
    by_vpc: dict[str, dict[str, str]] = {}
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = ec2.describe_subnets(**kwargs)
        for s in resp.get("Subnets", []):
            by_vpc.setdefault(s["VpcId"], {})[s["AvailabilityZone"]] = s["SubnetId"]
        token = resp.get("NextToken")
        if not token:
            break
    for vpc_id, az_to_subnet in by_vpc.items():
        if len(az_to_subnet) >= 2:
            subnet_ids = list(az_to_subnet.values())[:2]
            return vpc_id, subnet_ids, False

    octet = random.randint(0, 200)
    vpc = ec2.create_vpc(
        CidrBlock=f"10.{octet}.0.0/24",
        TagSpecifications=[{
            "ResourceType": "vpc",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-adassess-vpc-")}],
        }],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    azs = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"]][:2]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.{octet}.{i}.0/25",
            AvailabilityZone=az,
            TagSpecifications=[{
                "ResourceType": "subnet",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-adassess-subnet-")}],
            }],
        )["Subnet"]
        subnet_ids.append(subnet["SubnetId"])
    return vpc_id, subnet_ids, True


def _teardown_vpc(ec2, vpc_id, subnet_ids) -> None:
    for subnet_id in subnet_ids:
        _safe(lambda sid=subnet_id: ec2.delete_subnet(SubnetId=sid), "InvalidSubnetID.NotFound")
    _safe(lambda: ec2.delete_vpc(VpcId=vpc_id), "InvalidVpcID.NotFound")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
