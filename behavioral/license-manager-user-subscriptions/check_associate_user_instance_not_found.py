"""associate-user-instance-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "associate-user-instance-not-found"
GROUP = "error-semantics"
SERVICES = ["license-manager-user-subscriptions"]

_UNAUTHORIZED = "Unauthorized. Please check the request and access policy and try again."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateUser for a well-formed but nonexistent instance ID raises UnauthorizedException with its exact
    message, not ResourceNotFoundException."""
    lmus = ctx.client("license-manager-user-subscriptions")
    _ensure_slr(ctx)

    code, message = _error(
        lambda: lmus.associate_user(
            Username=ctx.unique_name("sim2real-user-"),
            InstanceId="i-0123456789abcdef0",
            IdentityProvider={"ActiveDirectoryIdentityProvider": {"DirectoryId": "d-0123456789"}},
        )
    )
    assert code == "UnauthorizedException", f"expected UnauthorizedException, got {code!r}"
    assert message == _UNAUTHORIZED, f"unexpected message: {message!r}"


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"].split(",")[0].strip(), exc.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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
