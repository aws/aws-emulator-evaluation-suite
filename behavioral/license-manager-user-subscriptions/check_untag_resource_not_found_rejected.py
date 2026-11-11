"""untag-resource-not-found-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "untag-resource-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["license-manager-user-subscriptions"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UntagResource and ListTagsForResource on a well-formed but never-created identity-provider ARN each
    raise BadRequestException "Invalid input resource arn"."""
    lmus = ctx.client("license-manager-user-subscriptions")
    _ensure_slr(ctx)
    arn = _fake_arn(ctx, "identity-provider", ctx.unique_name("sim2real-idp-"))

    code, message = _error(lambda: lmus.untag_resource(ResourceArn=arn, TagKeys=["env"]))
    assert code == "BadRequestException", f"expected BadRequestException from UntagResource, got {code!r}"
    assert message == "Invalid input resource arn", f"unexpected UntagResource message: {message!r}"

    tags_code, tags_message = _error(lambda: lmus.list_tags_for_resource(ResourceArn=arn))
    assert tags_code == "BadRequestException", (
        f"expected BadRequestException from ListTagsForResource on the same never-created ARN, got {tags_code!r}"
    )
    assert tags_message == "Invalid input resource arn", f"unexpected ListTagsForResource message: {tags_message!r}"


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
