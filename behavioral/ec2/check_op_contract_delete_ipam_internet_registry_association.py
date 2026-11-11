"""op-contract-delete-ipam-internet-registry-association."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-delete-ipam-internet-registry-association"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteIpamInternetRegistryAssociation with DryRun answers DryRunOperation; without DryRun a
    nonexistent association ID fails with InvalidIpamInternetRegistryAssociationId.NotFound, and
    DescribeIpamInternetRegistryAssociations rejects the same ID with that code (exact messages)."""
    ec2 = ctx.client("ec2")
    # AWS names the id form "ipam-internet-registry-assoc-<17 hex chars>" in its own
    # InvalidParameterValue message; a well-formed-but-nonexistent id exercises the NotFound
    # boundary rather than the Malformed one.
    fake_id = "ipam-internet-registry-assoc-00000000000000000"

    dry_run_code, dry_run_message = _error(
        lambda: ec2.delete_ipam_internet_registry_association(IpamInternetRegistryAssociationId=fake_id, DryRun=True)
    )
    assert dry_run_code == "DryRunOperation", f"expected DryRunOperation, got {dry_run_code!r}"
    assert dry_run_message == _DRY_RUN_MESSAGE, f"unexpected DryRunOperation message {dry_run_message!r}"

    code, message = _error(
        lambda: ec2.delete_ipam_internet_registry_association(IpamInternetRegistryAssociationId=fake_id)
    )
    assert code == "InvalidIpamInternetRegistryAssociationId.NotFound", f"unexpected error code {code!r}"
    assert message == f"The ipam-internet-registry-association ID '{fake_id}' does not exist", f"unexpected message {message!r}"

    # independent read at the destination, through a different operation than the one that was
    # rejected above: the id must not resolve to an association either way it can be asked.
    describe_code, describe_message = _error(
        lambda: ec2.describe_ipam_internet_registry_associations(
            IpamInternetRegistryAssociationIds=[fake_id]
        )
    )
    assert describe_code == "InvalidIpamInternetRegistryAssociationId.NotFound", f"unexpected error code {describe_code!r}"
    assert describe_message == f"The IPAM Internet Registry association ({fake_id}) does not exist.", f"unexpected message {describe_message!r}"


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises; a call that
    succeeds raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
