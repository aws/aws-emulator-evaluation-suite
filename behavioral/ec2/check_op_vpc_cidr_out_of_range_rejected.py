"""op-vpc-cidr-out-of-range-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-vpc-cidr-out-of-range-rejected"
GROUP = 'overly-permissive'
SERVICES = ['ec2']
#: The default service-class budget for the VpcLimitExceeded retry; the harness deadline bounds the run.
POLL_BUDGET_S = 300.0


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateVpc rejects CIDR blocks outside the allowed /16../28 netmask range.

    A valid /16 positive control shows the rejections are about the CIDR, not CreateVpc itself.
    """
    ec2 = ctx.client("ec2")

    good = _create_vpc_ignoring_quota(ec2, "10.0.0.0/16")
    vpc_id = good["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    assert good["Vpc"]["CidrBlock"] == "10.0.0.0/16", (
        f"expected the positive-control VPC to have CidrBlock 10.0.0.0/16, got {good['Vpc']['CidrBlock']}"
    )

    # The EC2 error-code table documents "InvalidVpcRange", but AWS returns "InvalidVpc.Range".
    # Too large (/8) and too small (/29) are both outside the allowed /16../28 netmask.
    for bad_cidr in ("10.0.0.0/8", "10.96.0.0/29"):
        resp = _error_code_ignoring_quota(ec2, lambda: ec2.create_vpc(CidrBlock=bad_cidr))
        err = resp.get("Error", {})
        status = resp.get("ResponseMetadata", {}).get("HTTPStatusCode")
        assert err.get("Code") == "InvalidVpc.Range", (
            f"expected InvalidVpc.Range for VPC CIDR {bad_cidr}, got {err.get('Code')!r}"
        )
        assert status == 400, f"expected HTTP 400 for VPC CIDR {bad_cidr}, got {status!r}"
        assert err.get("Message") == f"The CIDR '{bad_cidr}' is invalid.", (
            f"expected the InvalidVpc.Range message to name {bad_cidr}, got {err.get('Message')!r}"
        )
        created = ec2.describe_vpcs(Filters=[{"Name": "cidr", "Values": [bad_cidr]}])["Vpcs"]
        assert not created, f"a VPC with the refused CIDR {bad_cidr} exists: {[v['VpcId'] for v in created]!r}"


def _create_vpc_ignoring_quota(ec2, cidr: str, timeout_s: float = POLL_BUDGET_S):
    """CreateVpc a valid CIDR, retrying while masked by VpcLimitExceeded under concurrent load."""
    deadline = time.monotonic() + timeout_s
    attempt = 0
    while True:
        try:
            return ec2.create_vpc(
                CidrBlock=cidr,
                TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "VpcLimitExceeded" or time.monotonic() >= deadline:
                raise
            attempt += 1
            time.sleep(min(5 + attempt * 2, 20))

def _error_code(ec2, fn):
    """Call fn(); return its ClientError response. An unexpected success deletes the wrongly
    created VPC, then raises."""
    try:
        resp = fn()
    except ClientError as exc:
        return exc.response
    vpc_id = resp["Vpc"]["VpcId"]
    ec2.delete_vpc(VpcId=vpc_id)
    raise AssertionError(
        f"real AWS rejects this CIDR, but CreateVpc SUCCEEDED and returned {vpc_id}"
    )

def _error_code_ignoring_quota(ec2, fn, timeout_s: float = POLL_BUDGET_S):
    """_error_code(), but retry while the answer is masked by VPC quota.

    This check asserts a *validation* error from CreateVpc: under concurrent load
    EC2 enforces the quota before validating the CIDR, so a VpcLimitExceeded
    answer says nothing about the behavior under test.
    """
    deadline = time.monotonic() + timeout_s
    attempt = 0
    while True:
        resp = _error_code(ec2, fn)
        if resp.get("Error", {}).get("Code") != "VpcLimitExceeded" or time.monotonic() >= deadline:
            return resp
        attempt += 1
        time.sleep(min(5 + attempt * 2, 20))

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
