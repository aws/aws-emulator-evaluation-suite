"""op-contract-describeIpamInternetRegistryAssociations."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeIpamInternetRegistryAssociations"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """DescribeIpamInternetRegistryAssociations filtered by a new IPAM's ID returns no associations, and
    DryRun answers DryRunOperation with its exact message."""
    ec2 = ctx.client("ec2")
    ipam_id = _create_ipam(ctx, ec2)

    resp = ec2.describe_ipam_internet_registry_associations(
        Filters=[{"Name": "ipam-id", "Values": [ipam_id]}]
    )
    associations = resp.get("IpamInternetRegistryAssociations", [])
    assert associations == [], f"expected no associations for a fresh IPAM, got {associations}"

    code, message = _error(
        lambda: ec2.describe_ipam_internet_registry_associations(DryRun=True)
    )
    assert code == "DryRunOperation", f"unexpected error code: {code}"
    assert message == (
        "Request would have succeeded, but DryRun flag is set."
    ), f"unexpected DryRunOperation message: {message!r}"


def _create_ipam(ctx, ec2) -> str:
    name = ctx.unique_name("sim2real-behav-ipam-")
    ipam = ec2.create_ipam(
        Description=name,
        TagSpecifications=[{"ResourceType": "ipam", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Ipam"]
    ipam_id = ipam["IpamId"]
    ctx.on_cleanup(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True))
    return ipam_id


def _error(fn):
    """Call fn() and return the (code, message) of the error it raises. A call
    that SUCCEEDS raises AssertionError: real AWS refuses it, so acceptance must
    not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
