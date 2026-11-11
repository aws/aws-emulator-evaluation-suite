"""list-instances-missing-permission-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-instances-missing-permission-rejected"
GROUP = "overly-permissive"
SERVICES = ["license-manager-user-subscriptions"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListInstances signed by a user with no license-manager-user-subscriptions permissions raises
    AccessDeniedException with its exact message, while the same call with the default credentials succeeds."""
    iam = ctx.client("iam")
    _ensure_slr(ctx)
    user_name = ctx.unique_name("sim2real-lmus-noperm-")
    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"]))

    from botocore.exceptions import ClientError

    # Same target as ctx.client(), signed as the unprivileged user.
    default_client = ctx.client("license-manager-user-subscriptions")
    unpriv = ctx.client(
        "license-manager-user-subscriptions",
        creds={"aws_access_key_id": key["AccessKeyId"], "aws_secret_access_key": key["SecretAccessKey"]},
    )

    # freshly minted IAM credentials can take a while to become usable; both
    # InvalidClientTokenId and UnrecognizedClientException are transient signatures
    # of "the access key hasn't propagated yet" on real AWS, so retry past that
    # propagation window rather than treating either as the final result.
    code = message = None
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        try:
            unpriv.list_instances()
            raise AssertionError("expected the unprivileged caller's ListInstances call to be rejected")
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            if code in ("InvalidClientTokenId", "UnrecognizedClientException"):
                time.sleep(3.0)
                continue
            break

    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}"
    action = "license-manager-user-subscriptions:ListInstances"
    expected = (
        f"User: arn:aws:iam::{ctx.account}:user/{user_name} is not authorized to perform: {action} "
        f"on resource: arn:aws:license-manager-user-subscriptions:{ctx.region}:{ctx.account}:/instance/ListInstances "
        f"because no identity-based policy allows the {action} action"
    )
    assert message == expected, f"unexpected message: {message!r}"

    # positive control: the default, permissioned client succeeds
    resp = default_client.list_instances()
    assert "InstanceSummaries" in resp, (
        f"expected the permissioned caller's ListInstances response to contain "
        f"'InstanceSummaries', got keys {sorted(resp.keys())!r}"
    )


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

    lmus_iam = ctx.client("iam")
    try:
        lmus_iam.create_service_linked_role(
            AWSServiceName="license-manager-user-subscriptions.amazonaws.com"
        )
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
