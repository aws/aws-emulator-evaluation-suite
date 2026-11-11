"""op-contract-enableIpamInternetRegistryAssociation."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "op-contract-enableIpamInternetRegistryAssociation"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """EnableIpamInternetRegistryAssociation on a placeholder association ID answers DryRun with
    DryRunOperation and the real call with InvalidIpamInternetRegistryAssociationId.Malformed, each
    with its exact message."""
    ec2 = ctx.client("ec2")
    association_id = "ipam-ira-00000000000000000"
    kwargs = dict(
        IpamInternetRegistryAssociationId=association_id,
        ChildHandle="child-handle-example",
        ParentHandle="parent-handle-example",
        ParentBpkiTa="-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
        RpkiVersion="1",
        ServiceUri="https://rpki.example.com/",
    )

    dry_run_code, dry_run_message = _client_error(
        lambda: ec2.enable_ipam_internet_registry_association(DryRun=True, **kwargs)
    )
    assert dry_run_code == "DryRunOperation", f"expected DryRunOperation, got {dry_run_code}"
    expected_dry = "Request would have succeeded, but DryRun flag is set."
    assert dry_run_message == expected_dry, f"expected message {expected_dry!r}, got {dry_run_message!r}"

    real_code, real_message = _client_error(lambda: ec2.enable_ipam_internet_registry_association(**kwargs))
    assert real_code == "InvalidIpamInternetRegistryAssociationId.Malformed", (
        f"expected InvalidIpamInternetRegistryAssociationId.Malformed, got {real_code}"
    )
    expected_real = f"The ipam-internet-registry-association ID '{association_id}' is malformed"
    assert real_message == expected_real, f"expected message {expected_real!r}, got {real_message!r}"
    assert real_code != dry_run_code, (
        f"expected a distinct error boundary for the real call vs DryRun, both got {real_code}"
    )


def _client_error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn() and return the (code, message) of the ClientError it raises. A call that succeeds
    raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
