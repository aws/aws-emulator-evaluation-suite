"""op-contract-get-managed-resource-visibility."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-get-managed-resource-visibility"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetManagedResourceVisibility returns a well-formed account-level setting that does
    not drift across reads, and its DryRun boundary is honored exactly as documented.
    """
    ec2 = ctx.client("ec2")

    # success-path contract: a well-formed visibility setting is always returned, taking
    # one of the two documented values. Membership alone can't fail (it's the full
    # modelled enum), so pair it with a freeze check: an unrelated read must not advance
    # or flap the value between calls.
    resp = ec2.get_managed_resource_visibility()
    default_visibility = resp["Visibility"]["DefaultVisibility"]
    assert default_visibility in ("hidden", "visible"), (
        f"unexpected DefaultVisibility value: {default_visibility!r}"
    )

    resp2 = ec2.get_managed_resource_visibility()
    default_visibility2 = resp2["Visibility"]["DefaultVisibility"]
    assert default_visibility2 == default_visibility, (
        f"GetManagedResourceVisibility is not idempotent on a plain read: "
        f"{default_visibility!r} then {default_visibility2!r}"
    )

    # error boundary: DryRun short-circuits with DryRunOperation when authorized,
    # distinct from an actual (successful) call.
    code, message, _ = _client_error(lambda: ec2.get_managed_resource_visibility(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    assert message == "Request would have succeeded, but DryRun flag is set.", f"unexpected DryRunOperation message: {message!r}"


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
