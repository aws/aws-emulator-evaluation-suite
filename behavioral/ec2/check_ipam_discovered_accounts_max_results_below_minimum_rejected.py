"""ipam-discovered-accounts-max-results-below-minimum-rejected."""
from __future__ import annotations

from botocore.config import Config

from behavioral_harness import tags

CHECK = "ipam-discovered-accounts-max-results-below-minimum-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """GetIpamDiscoveredAccounts, sent without client-side validation, rejects a MaxResults below
    100 with InvalidMaxResults and "The number of requested max results must be between 100 and
    1000." and accepts MaxResults=100.
    """
    ec2 = ctx.client("ec2")
    resource_discovery_id = _create_ipam_with_discovery(ctx, ec2)

    raw_ec2 = ctx.client("ec2", config=Config(parameter_validation=False))
    code, message = _error(
        lambda: raw_ec2.get_ipam_discovered_accounts(
            IpamResourceDiscoveryId=resource_discovery_id,
            DiscoveryRegion=ctx.region,
            MaxResults=1,
        )
    )
    assert code == "InvalidMaxResults", f"expected InvalidMaxResults, got {code!r}"
    assert message == "The number of requested max results must be between 100 and 1000.", f"unexpected InvalidMaxResults message {message!r}"

    # Positive control: the service's actual minimum (100) is accepted, not rejected.
    resp = ec2.get_ipam_discovered_accounts(
        IpamResourceDiscoveryId=resource_discovery_id,
        DiscoveryRegion=ctx.region,
        MaxResults=100,
    )
    assert "IpamDiscoveredAccounts" in resp, sorted(resp)
    assert isinstance(resp["IpamDiscoveredAccounts"], list), (
        f"expected IpamDiscoveredAccounts to be a list, got {resp['IpamDiscoveredAccounts']!r}"
    )


def _create_ipam_with_discovery(ctx, ec2) -> str:
    name = ctx.unique_name("sim2real-behav-ipam-")
    ipam = _create_ipam_with_retry(
        ctx, ec2,
        Description=name,
        OperatingRegions=[{"RegionName": ctx.region}],
        TagSpecifications=[{"ResourceType": "ipam", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    ctx.on_cleanup(lambda: ec2.delete_ipam(IpamId=ipam["IpamId"], Cascade=True))
    return ipam["DefaultResourceDiscoveryId"]


def _create_ipam_with_retry(ctx, ec2, **kwargs):
    """CreateIpam, retrying ONLY the per-Region quota refusal (IPAMs per Region is 1 by default)
    while another IPAM finishes deleting, every 2 s to a deadline capped by ctx.time_left()."""
    import time
    from botocore.exceptions import ClientError

    left = ctx.time_left()
    cap = 480.0 if left is None else min(480.0, left)
    deadline = time.monotonic() + cap
    while True:
        try:
            return ec2.create_ipam(**kwargs)["Ipam"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceLimitExceeded":
                raise
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"no IPAM slot freed within {cap:.0f} s: "
                    f"{err.response['Error'].get('Message')!r}"
                ) from err
            time.sleep(2)


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
