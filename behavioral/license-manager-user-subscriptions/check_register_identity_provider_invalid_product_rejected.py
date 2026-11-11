"""register-identity-provider-invalid-product-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "register-identity-provider-invalid-product-rejected"
GROUP = "overly-permissive"
SERVICES = ["license-manager-user-subscriptions"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RegisterIdentityProvider with an unknown Product raises ValidationException "Invalid product
    NOT_A_REAL_PRODUCT_XYZ", while a valid Product with the same nonexistent directory raises
    ValidationException naming the directory instead: the Product value is inspected."""
    lmus = ctx.client("license-manager-user-subscriptions")
    _ensure_slr(ctx)
    settings = {"Subnets": ["subnet-0123456789abcdef0"], "SecurityGroupId": "sg-0123456789abcdef0"}

    code, message = _error(
        lambda: lmus.register_identity_provider(
            IdentityProvider={"ActiveDirectoryIdentityProvider": {"DirectoryId": "d-0123456789"}},
            Product="NOT_A_REAL_PRODUCT_XYZ",
            Settings=settings,
        )
    )
    assert code == "ValidationException", str(code)
    assert message == "Invalid product NOT_A_REAL_PRODUCT_XYZ", message

    code2, message2 = _error(
        lambda: lmus.register_identity_provider(
            IdentityProvider={"ActiveDirectoryIdentityProvider": {"DirectoryId": "d-0123456789"}},
            Product="OFFICE_STANDARD",
            Settings=settings,
        )
    )
    assert code2 == "ValidationException", str(code2)
    assert message2 == "d-0123456789 directory either cannot be found or is not in active state", message2


def _error(fn):
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
