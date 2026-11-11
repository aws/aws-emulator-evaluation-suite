"""op-contract-get-ipam-internet-registry-association-cidrs."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-get-ipam-internet-registry-association-cidrs"
GROUP = "error-semantics"
SERVICES = ["ec2"]
DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """GetIpamInternetRegistryAssociationCidrs returns an empty CIDR list for a freshly created IPAM
    internet-registry association; DryRun fails with DryRunOperation and the standard message."""
    ec2 = ctx.client("ec2")
    association_id = _create_internet_registry_association(ctx, ec2)

    resp = ec2.get_ipam_internet_registry_association_cidrs(
        IpamInternetRegistryAssociationId=association_id
    )
    cidrs = _list_field(resp, "IpamInternetRegistryAssociationCidrSet", "IpamInternetRegistryAssociationCidrs")
    assert cidrs == [], f"expected no registered CIDRs for a freshly created association, got {cidrs}"

    code, message = _client_error(
        lambda: ec2.get_ipam_internet_registry_association_cidrs(
            IpamInternetRegistryAssociationId=association_id, DryRun=True
        )
    )
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    assert message == DRY_RUN_MESSAGE, f"expected message {DRY_RUN_MESSAGE!r}, got {message!r}"


def _list_field(resp: dict, *candidates: str) -> list:
    for key in candidates:
        if key in resp:
            return resp[key]
    for key, value in resp.items():
        if key != "ResponseMetadata" and isinstance(value, list):
            return value
    raise AssertionError(f"no list-valued field found in response: {sorted(resp)}")


def _create_internet_registry_association(ctx, ec2) -> str:
    from botocore.exceptions import ClientError

    name = ctx.unique_name("sim2real-behav-ipam-")
    ipam = _create_ipam_with_retry(
        ec2,
        Description=name,
        Tier="advanced",
        OperatingRegions=[{"RegionName": ctx.region}],
        TagSpecifications=[{"ResourceType": "ipam", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    ipam_id = ipam["IpamId"]
    ctx.on_cleanup(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True))

    try:
        assoc = ec2.create_ipam_internet_registry_association(
            IpamId=ipam_id,
            Rir="arin",
            OrganizationHandle=ctx.unique_name("SIM2REAL-TEST-"),
            ClientToken=ctx.unique_name("sim2real-behav-assoc-"),
        )["IpamInternetRegistryAssociation"]
    except ClientError as err:
        raise AssertionError(
            f"cannot establish a real IPAM internet registry association: "
            f"{err.response['Error']['Code']}"
        )
    association_id = assoc["IpamInternetRegistryAssociationId"]
    ctx.on_cleanup(lambda: _delete_association(ec2, association_id))
    return association_id


def _delete_association(ec2, association_id: str, timeout_s: float = 120.0) -> None:
    """Delete the association, waiting out its create-in-progress window: AWS
    refuses the delete with IncorrectState until the create settles. An
    association that is already gone counts as deleted."""
    import time
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_ipam_internet_registry_association(
                IpamInternetRegistryAssociationId=association_id
            )
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code.endswith(".NotFound"):
                return
            if code != "IncorrectState" or time.monotonic() >= deadline:
                raise
        time.sleep(10)


def _create_ipam_with_retry(ec2, **kwargs):
    """The per-account Ipam quota is small and shared across every behavioral
    check that creates one; a prior run's Ipam can be left over (e.g. an
    interrupted process) and exhaust it. Clean up stray sim2real Ipams and
    retry a bounded number of times before giving up."""
    import time
    from botocore.exceptions import ClientError

    last_err = None
    for attempt in range(4):
        try:
            return ec2.create_ipam(**kwargs)["Ipam"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceLimitExceeded":
                raise
            last_err = err
            _delete_stray_ipams(ec2)
            time.sleep(5)
    raise AssertionError(f"account Ipam quota exhausted even after cleanup: {last_err}")


def _delete_stray_ipams(ec2) -> None:
    from botocore.exceptions import ClientError

    try:
        ipams = ec2.describe_ipams()["Ipams"]
    except ClientError:
        return
    for ipam in ipams:
        tag_map = {t["Key"]: t["Value"] for t in ipam.get("Tags", [])}
        if tag_map.get("Name", "").startswith("sim2real-behav-"):
            try:
                ec2.delete_ipam(IpamId=ipam["IpamId"], Cascade=True)
            except ClientError:
                pass


def _client_error(fn):
    """Call fn(); return its botocore error as (code, message). An unexpected SUCCESS
    raises, so a target that accepts what AWS refuses is not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
