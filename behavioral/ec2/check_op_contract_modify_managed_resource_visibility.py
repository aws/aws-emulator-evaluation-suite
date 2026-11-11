"""op-contract-modify-managed-resource-visibility."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-modify-managed-resource-visibility"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyManagedResourceVisibility: DryRun surfaces the authorization contract, and a
    real toggle is reflected by GetManagedResourceVisibility (restored on cleanup since
    this is an account-wide setting)."""
    ec2 = ctx.client("ec2")
    if not hasattr(ec2, "modify_managed_resource_visibility"):
        raise AssertionError("botocore in this environment lacks ModifyManagedResourceVisibility")

    original = ec2.get_managed_resource_visibility()["Visibility"]["DefaultVisibility"]
    ctx.on_cleanup(lambda: ec2.modify_managed_resource_visibility(DefaultVisibility=original))
    new_value = "hidden" if original == "visible" else "visible"

    # error boundary: DryRun reports the auth contract without mutating state
    err, message = _error(
        lambda: ec2.modify_managed_resource_visibility(DefaultVisibility=new_value, DryRun=True)
    )
    assert err == "DryRunOperation", f"expected DryRunOperation, got {err!r}"
    assert message == "Request would have succeeded, but DryRun flag is set.", message
    unchanged = ec2.get_managed_resource_visibility()["Visibility"]["DefaultVisibility"]
    assert unchanged == original, (
        f"DryRun must not mutate the setting: expected {original!r}, got {unchanged!r}"
    )

    # success path: a real call flips and persists the account-wide setting
    resp = ec2.modify_managed_resource_visibility(DefaultVisibility=new_value)
    got = resp["Visibility"]["DefaultVisibility"]
    assert got == new_value, (
        f"expected ModifyManagedResourceVisibility to echo {new_value!r}, got {got!r}"
    )
    confirmed = ec2.get_managed_resource_visibility()["Visibility"]["DefaultVisibility"]
    assert confirmed == new_value, (
        f"expected GetManagedResourceVisibility to read back {new_value!r}, got {confirmed!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
