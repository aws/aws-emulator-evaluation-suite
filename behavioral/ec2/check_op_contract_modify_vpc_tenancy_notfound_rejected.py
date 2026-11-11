"""op-contract-modify-vpc-tenancy-notfound-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-modify-vpc-tenancy-notfound-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyVpcTenancy: success flips a dedicated-tenancy VPC back to default and
    DescribeVpcs reflects the change; a nonexistent VpcId is rejected with the
    documented InvalidVpcID.NotFound boundary."""
    ec2 = ctx.client("ec2")

    vpc = _create_vpc_with_retry(
        ec2,
        CidrBlock="10.222.0.0/16",
        InstanceTenancy="dedicated",
        TagSpecifications=_tag_spec(ctx, "vpc", "tenancy-vpc"),
    )
    vpc_id = vpc["VpcId"]
    # A bare single-attempt delete_vpc can transiently hit DependencyViolation if
    # some sibling-created dependency in the account is still settling; retry the
    # delete through a bounded window instead of letting one failed attempt
    # silently leak the VPC (the runner swallows cleanup exceptions), which would
    # otherwise permanently eat into the account's shared VPC quota.
    ctx.on_cleanup(lambda: _delete_vpc_with_retry(ec2, vpc_id))
    assert vpc["InstanceTenancy"] == "dedicated", vpc

    # error boundary: a genuinely-allocated VPC id that has since been deleted, not a
    # fabricated hex sentinel. Measured on real AWS: ModifyVpcTenancy validates its
    # VpcId more strictly than DescribeVpcs/DeleteVpc do — the fabricated sentinel
    # "vpc-0123456789abcdef0" that ~100 other ec2 checks use to hit NotFound on other
    # operations instead comes back InvalidVpcId.Malformed here. A real id that WAS
    # issued and then deleted is unambiguously the NotFound case.
    deleted_vpc_id = _create_vpc_with_retry(
        ec2, CidrBlock="10.223.0.0/16", TagSpecifications=_tag_spec(ctx, "vpc", "deleted-vpc")
    )["VpcId"]
    _delete_vpc_with_retry(ec2, deleted_vpc_id)
    err, err_message = _client_error(lambda: ec2.modify_vpc_tenancy(VpcId=deleted_vpc_id, InstanceTenancy="default"))
    assert err == "InvalidVpcID.NotFound", err
    expected_message = f"The vpc ID '{deleted_vpc_id}' does not exist"
    assert err_message == expected_message, f"expected message {expected_message!r}, got {err_message!r}"

    # success path: dedicated -> default is the only supported transition.
    resp = ec2.modify_vpc_tenancy(VpcId=vpc_id, InstanceTenancy="default")
    assert resp["ReturnValue"] is True, resp

    updated = _poll_until(
        lambda: ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0],
        lambda v: v["InstanceTenancy"] == "default",
        timeout_s=60,
        interval_s=5,
    )
    assert updated["InstanceTenancy"] == "default", updated


def _tag_spec(ctx, resource_type, prefix):
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{prefix}-")}]}]


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_vpc_with_retry(ec2, timeout_s=900.0, interval_s=20.0, **kwargs):
    # The account's VPC limit can be transiently exhausted by other checks
    # running concurrently in the same account/region that haven't finished
    # tearing down their own VPCs yet. A sibling can legitimately hold its VPC
    # for several minutes end-to-end (provisioning + assertions + its own
    # bounded polls) before releasing it, so a short retry window gives up too
    # early on real AWS — widen it enough to realistically outlast a sibling's
    # full lifecycle rather than just a brief blip, so this check only fails
    # for a real, sustained quota problem.
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ec2.create_vpc(**kwargs)["Vpc"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "VpcLimitExceeded" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _delete_vpc_with_retry(ec2, vpc_id, timeout_s=180.0, interval_s=10.0):
    # Mirrors the create-side retry: a bare single-attempt delete_vpc can
    # transiently hit DependencyViolation while some just-deleted dependency
    # finishes settling. Retry through that window so this cleanup can't
    # silently leak the VPC (the runner swallows cleanup exceptions), which
    # would otherwise permanently eat into the account's shared VPC quota.
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_vpc(VpcId=vpc_id)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "DependencyViolation" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not observed within {timeout_s}s; last saw {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
