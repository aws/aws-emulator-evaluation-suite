"""op-contract-get-ipam-routing-policy-registrations."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-get-ipam-routing-policy-registrations"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_PLACEHOLDER_ASSOCIATION_ID = "ipam-ira-0aaaaaaaaaaaaaaaa"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetIpamRoutingPolicyRegistrations with DryRun fails with DryRunOperation and the standard message;
    without DryRun the same placeholder association id fails with HTTP 400,
    InvalidIpamInternetRegistryAssociationId.Malformed and its exact message."""

    ec2 = ctx.client("ec2")
    if not hasattr(ec2, "get_ipam_routing_policy_registrations"):
        raise AssertionError(
            "unreachable: installed botocore lacks get_ipam_routing_policy_registrations "
            "(IPAM routing policy registration is a very recent EC2 feature)"
        )

    dry_run_code, dry_run_message, _ = _client_error(
        lambda: ec2.get_ipam_routing_policy_registrations(
            IpamInternetRegistryAssociationId=_PLACEHOLDER_ASSOCIATION_ID, DryRun=True
        )
    )
    assert dry_run_code == "DryRunOperation", (
        f"expected DryRunOperation for an authorized DryRun call, got {dry_run_code!r}"
    )
    assert dry_run_message == "Request would have succeeded, but DryRun flag is set.", f"unexpected DryRunOperation message: {dry_run_message!r}"

    real_code, real_message, status = _client_error(
        lambda: ec2.get_ipam_routing_policy_registrations(
            IpamInternetRegistryAssociationId=_PLACEHOLDER_ASSOCIATION_ID
        )
    )
    assert status == 400, f"expected a client (400) error, got HTTP {status}"
    assert real_code == "InvalidIpamInternetRegistryAssociationId.Malformed", (
        "expected the specific id-validation rejection for this placeholder "
        f"association id, got {real_code!r}"
    )
    assert real_message == f"The ipam-internet-registry-association ID '{_PLACEHOLDER_ASSOCIATION_ID}' is malformed", f"unexpected {real_code} message: {real_message!r}"


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
