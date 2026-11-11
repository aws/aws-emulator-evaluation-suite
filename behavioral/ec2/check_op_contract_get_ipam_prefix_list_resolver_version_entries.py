"""op-contract-get-ipam-prefix-list-resolver-version-entries."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-get-ipam-prefix-list-resolver-version-entries"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_PLACEHOLDER_RESOLVER_ID = "ipam-plr-0000000000000000"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetIpamPrefixListResolverVersionEntries: DryRun confirms the permission-check
    contract, and turning DryRun off surfaces a concrete rejection for the same call.
    """

    ec2 = ctx.client("ec2")
    if not hasattr(ec2, "get_ipam_prefix_list_resolver_version_entries"):
        raise AssertionError(
            "unreachable: installed botocore lacks get_ipam_prefix_list_resolver_version_entries "
            "(IPAM prefix list resolver is a very recent EC2 feature)"
        )

    dry_run_code, dry_run_message, _ = _client_error(
        lambda: ec2.get_ipam_prefix_list_resolver_version_entries(
            IpamPrefixListResolverId=_PLACEHOLDER_RESOLVER_ID,
            IpamPrefixListResolverVersion=1,
            DryRun=True,
        )
    )
    assert dry_run_code == "DryRunOperation", (
        f"expected DryRunOperation for an authorized DryRun call, got {dry_run_code!r}"
    )
    assert dry_run_message == "Request would have succeeded, but DryRun flag is set.", f"unexpected DryRunOperation message: {dry_run_message!r}"

    real_code, real_message, status = _client_error(
        lambda: ec2.get_ipam_prefix_list_resolver_version_entries(
            IpamPrefixListResolverId=_PLACEHOLDER_RESOLVER_ID,
            IpamPrefixListResolverVersion=1,
        )
    )
    assert real_code == "InvalidIpamPrefixListResolverId.NotFound", (
        f"expected InvalidIpamPrefixListResolverId.NotFound for a well-formed but "
        f"nonexistent resolver id, got {real_code!r}"
    )
    assert real_message == f"The ipam-prefix-list-resolver ID '{_PLACEHOLDER_RESOLVER_ID}' does not exist", f"unexpected {real_code} message: {real_message!r}"
    assert status == 400, f"expected a client (400) error, got HTTP {status}"


def _client_error(fn):
    """Call fn() and return (code, message, http_status) of the ClientError it raises.
    An unexpected success raises AssertionError rather than returning a falsy value."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message"), exc.response["ResponseMetadata"]["HTTPStatusCode"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
