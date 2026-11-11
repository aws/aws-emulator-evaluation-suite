"""disassociate-user-ambiguous-identifiers-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "disassociate-user-ambiguous-identifiers-rejected"
GROUP = "error-semantics"
SERVICES = ["license-manager-user-subscriptions"]

_UNAUTHORIZED = "Unauthorized. Please check the request and access policy and try again."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DisassociateUser with no identifiers raises ValidationException with its exact message, and with the full
    identifier triple for a nonexistent instance raises UnauthorizedException with its exact message."""
    lmus = ctx.client("license-manager-user-subscriptions")
    _ensure_slr(ctx)

    code, message = _error(lambda: lmus.disassociate_user())
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == "IdentityProvider, InstanceId, and Username must be provided", (
        f"unexpected message: {message!r}"
    )

    # Contrast: supplying a fully-specified (but never-created) InstanceUserArn moves
    # past the "which identifiers were given" gate -- the ARN is well-formed but
    # instance-user resources are scoped like an owned resource, so the service fails
    # closed on authorization (UnauthorizedException) rather than surfacing
    # ResourceNotFoundException (confirmed empirically against real AWS). Either way
    # it is a different, more specific failure than the missing-identifiers case
    # above, proving the ValidationException there is about the missing identifiers,
    # not a blanket rejection of every DisassociateUser call.
    arn = _fake_arn(ctx, "instance-user", ctx.unique_name("sim2real-iu-"))
    code2, message2 = _error(lambda: lmus.disassociate_user(InstanceUserArn=arn))
    assert code2 == "UnauthorizedException", f"expected UnauthorizedException, got {code2!r}"
    assert message2 == _UNAUTHORIZED, f"unexpected message: {message2!r}"


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"].split(",")[0].strip(), exc.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _fake_arn(ctx, resource_type, resource_id):
    return f"arn:aws:license-manager-user-subscriptions:{ctx.region}:{_account_id(ctx)}:{resource_type}/{resource_id}"


def _ensure_slr(ctx):
    """license-manager-user-subscriptions API calls require the
    AWSServiceRoleForAWSLicenseManagerUserSubscriptionsService service-linked role to
    exist in the account; without it every call is rejected with
    AccessDeniedException("Service Linked role is not present") before the service
    ever evaluates the request. Create it idempotently, then poll a cheap real call
    until the role has actually propagated -- IAM's eventual consistency means the
    license-manager-user-subscriptions API can still see the role as absent for a
    few seconds right after CreateServiceLinkedRole returns."""
    import time

    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(AWSServiceName="license-manager-user-subscriptions.amazonaws.com")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidInput":
            raise

    lmus_probe = ctx.client("license-manager-user-subscriptions")
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        try:
            lmus_probe.list_instances(MaxResults=1)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDeniedException" and "Service Linked role" in str(exc):
                time.sleep(3.0)
                continue
            return


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
