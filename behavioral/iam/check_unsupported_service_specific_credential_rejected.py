"""unsupported-service-specific-credential-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "unsupported-service-specific-credential-rejected"
GROUP = 'errors'
SERVICES = ['iam']


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateServiceSpecificCredential rejects ServiceName ec2.amazonaws.com (not on IAM's
    supported list) with NoSuchEntity and its exact message and stores nothing, while
    codecommit.amazonaws.com succeeds for the same user."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-behav-user-")
    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    code, message = _error(
        lambda: iam.create_service_specific_credential(
            UserName=user_name, ServiceName="ec2.amazonaws.com"
        )
    )
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code}"
    expected = "No such service ec2.amazonaws.com is supported for Service Specific Credentials"
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    creds_after_reject = iam.list_service_specific_credentials(UserName=user_name)[
        "ServiceSpecificCredentials"
    ]
    assert creds_after_reject == [], (
        f"rejected CreateServiceSpecificCredential must not persist anything: {creds_after_reject}"
    )

    # ListServiceSpecificCredentials itself validates ServiceName the same way.
    code_list, message_list = _error(
        lambda: iam.list_service_specific_credentials(
            UserName=user_name, ServiceName="ec2.amazonaws.com"
        )
    )
    assert code_list == "NoSuchEntity", (
        f"ListServiceSpecificCredentials: expected NoSuchEntity, got {code_list}"
    )
    expected = "No such service ec2.amazonaws.com is supported for Service Specific Credentials"
    assert message_list == expected, f"expected message {expected!r}, got {message_list!r}"

    created = iam.create_service_specific_credential(
        UserName=user_name, ServiceName="codecommit.amazonaws.com"
    )
    cred_id = created["ServiceSpecificCredential"]["ServiceSpecificCredentialId"]
    ctx.on_cleanup(
        lambda: iam.delete_service_specific_credential(
            UserName=user_name, ServiceSpecificCredentialId=cred_id
        )
    )
    creds_after_accept = iam.list_service_specific_credentials(UserName=user_name)[
        "ServiceSpecificCredentials"
    ]
    accepted_ids = [c["ServiceSpecificCredentialId"] for c in creds_after_accept]
    assert cred_id in accepted_ids, (
        f"expected {cred_id} in the post-accept listing, got {accepted_ids}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
