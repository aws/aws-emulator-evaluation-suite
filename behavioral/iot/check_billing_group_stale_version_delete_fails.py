"""billing-group-stale-version-delete-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "billing-group-stale-version-delete-fails"
GROUP = 'overly-permissive'
SERVICES = ['iot']

def _err(fn):
    """Call fn(); return the (code, message) of the ClientError it raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

def _delete_billing_group(iot, name):
    """Best-effort teardown: delete a billing group (thing associations dissolve with it)."""
    iot.delete_billing_group(billingGroupName=name)

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteBillingGroup with a stale expectedVersion must fail with VersionConflictException,
    leave the group untouched, and the identical call with the correct version must then delete
    it for real."""
    iot = ctx.client("iot")
    group = ctx.unique_name("sim2real-behav-bg-ver-")
    iot.create_billing_group(billingGroupName=group, tags=[{"Key": "sim2real-check", "Value": CHECK}])
    ctx.on_cleanup(lambda _n=group: _delete_billing_group(iot, _n))

    real_version = iot.describe_billing_group(billingGroupName=group)["version"]

    code = _err(
        lambda: iot.delete_billing_group(
            billingGroupName=group, expectedVersion=real_version + 999
        )
    )
    assert code == ("VersionConflictException", f"The version for billing group {group} does not match the expected version."), (
        f"expected VersionConflictException for the stale expectedVersion, got {code!r}"
    )

    # The group must still exist, at the same version, after the rejected delete.
    still = iot.describe_billing_group(billingGroupName=group)
    assert still["billingGroupName"] == group, f"expected {group} to survive the rejected delete, got {still}"
    assert still["version"] == real_version, (
        f"expected version to remain {real_version} after the rejected delete, got {still['version']}"
    )

    # Positive control: the identical call with the correct expectedVersion now succeeds.
    iot.delete_billing_group(billingGroupName=group, expectedVersion=real_version)

    gone_code = _err(lambda: iot.describe_billing_group(billingGroupName=group))
    assert gone_code == ("ResourceNotFoundException", f"BillingGroup {ctx.account}:{group} not found."), (
        f"expected ResourceNotFoundException for the deleted billing group, got {gone_code!r}"
    )

    # DeleteBillingGroup models no not-found error (only InvalidRequestException,
    # VersionConflictException, ThrottlingException, InternalFailureException): a further delete
    # of the now-dead id is an idempotent no-op success on real AWS, not a rejection.
    try:
        iot.delete_billing_group(billingGroupName=group, expectedVersion=real_version)
    except ClientError as exc:
        raise AssertionError(
            f"expected the redelete of an already-deleted group to be a no-op success, got {exc!r}"
        ) from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
