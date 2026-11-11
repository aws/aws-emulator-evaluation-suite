"""op-contract-get-ipam-discovered-accounts."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-get-ipam-discovered-accounts"
GROUP = "error-semantics"
SERVICES = ["ec2"]
DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """GetIpamDiscoveredAccounts lists the calling account under the IPAM's default resource discovery
    (an IPAM monitors its home account); DryRun fails with DryRunOperation and the standard message."""
    ec2 = ctx.client("ec2")
    sts = ctx.client("sts")
    own_account_id = sts.get_caller_identity()["Account"]

    resource_discovery_id = _create_ipam_with_discovery(ctx, ec2)

    # A default resource discovery only reports an account once that account
    # actually owns a monitored resource (e.g. a VPC) in the discovery
    # region -- an account with no VPCs never shows up in
    # GetIpamDiscoveredAccounts, no matter how long you wait. Create a
    # throwaway VPC in the discovery region so the home account has
    # something for IPAM to discover.
    vpc_name = ctx.unique_name("sim2real-behav-ipam-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.211.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": vpc_name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    # The home account isn't necessarily discovered the instant the
    # resource discovery resource is created -- IPAM's discovery process
    # runs on its own schedule and the first pass can lag behind creation.
    # Poll with a bounded budget rather than assuming it's immediate.
    accounts = _poll_until_discovered(ec2, resource_discovery_id, ctx.region)
    assert isinstance(accounts, list) and len(accounts) >= 1, accounts
    account_ids = {a["AccountId"] for a in accounts}
    assert own_account_id in account_ids, (own_account_id, account_ids)

    code, message = _client_error(
        lambda: ec2.get_ipam_discovered_accounts(
            IpamResourceDiscoveryId=resource_discovery_id,
            DiscoveryRegion=ctx.region,
            DryRun=True,
        )
    )
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    assert message == DRY_RUN_MESSAGE, f"expected message {DRY_RUN_MESSAGE!r}, got {message!r}"


def _poll_until_discovered(ec2, resource_discovery_id: str, region: str, attempts: int = 40, delay: float = 20.0) -> list:
    import time

    last_accounts: list = []
    for _ in range(attempts):
        resp = ec2.get_ipam_discovered_accounts(
            IpamResourceDiscoveryId=resource_discovery_id, DiscoveryRegion=region
        )
        last_accounts = _list_field(resp, "IpamDiscoveredAccounts", "IpamDiscoveredAccountSet")
        if last_accounts:
            return last_accounts
        time.sleep(delay)
    raise AssertionError(
        f"no discovered accounts within {attempts * delay}s, last value: {last_accounts}"
    )


def _list_field(resp: dict, *candidates: str) -> list:
    """The exact response key for this rarely-used operation isn't reliably
    documented across API versions; accept any of the likely names and, failing
    that, fall back to the sole list-valued field actually present."""
    for key in candidates:
        if key in resp:
            return resp[key]
    for key, value in resp.items():
        if key != "ResponseMetadata" and isinstance(value, list):
            return value
    raise AssertionError(f"no list-valued field found in response: {sorted(resp)}")


def _create_ipam_with_discovery(ctx, ec2) -> str:
    name = ctx.unique_name("sim2real-behav-ipam-")
    ipam = _create_ipam_with_retry(
        ec2,
        Description=name,
        OperatingRegions=[{"RegionName": ctx.region}],
        TagSpecifications=[{"ResourceType": "ipam", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    ctx.on_cleanup(lambda: ec2.delete_ipam(IpamId=ipam["IpamId"], Cascade=True))
    return ipam["DefaultResourceDiscoveryId"]


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
