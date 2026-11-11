"""update-identity-provider-settings-overlapping-subnets-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-identity-provider-settings-overlapping-subnets-rejected"
GROUP = "error-semantics"
SERVICES = ["license-manager-user-subscriptions"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateIdentityProviderSettings on a nonexistent IdentityProviderArn raises ValidationException "Identity
    provider is not valid" both with overlapping and with disjoint subnet changes: the ARN is resolved before
    the payload is evaluated."""
    lmus = ctx.client("license-manager-user-subscriptions")
    _ensure_slr(ctx)
    arn = _fake_arn(ctx, "identity-provider", ctx.unique_name("sim2real-idp-"))

    overlap_code, overlap_msg = _error_code_and_message(
        lambda: lmus.update_identity_provider_settings(
            IdentityProviderArn=arn,
            UpdateSettings={
                "AddSubnets": ["subnet-0123456789abcdef0"],
                "RemoveSubnets": ["subnet-0123456789abcdef0"],
            },
        )
    )
    assert overlap_code == "ValidationException", f"expected ValidationException, got {overlap_code!r}"
    assert overlap_msg == "Identity provider is not valid", f"unexpected message: {overlap_msg!r}"

    control_code, control_msg = _error_code_and_message(
        lambda: lmus.update_identity_provider_settings(
            IdentityProviderArn=arn,
            UpdateSettings={
                "AddSubnets": ["subnet-0123456789abcdef0"],
                "RemoveSubnets": ["subnet-0fedcba9876543210"],
            },
        )
    )
    assert (control_code, control_msg) == (overlap_code, overlap_msg), (
        "expected the non-overlapping control to fail identically -- ARN resolution, not "
        f"subnet overlap, is what UpdateIdentityProviderSettings validates first -- got "
        f"{(control_code, control_msg)!r} vs overlapping-subnets call {(overlap_code, overlap_msg)!r}"
    )


def _error_code_and_message(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        code = exc.response["Error"]["Code"].split(",")[0].strip()
        return code, exc.response["Error"].get("Message", "")
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
