"""service-specific-credential-cross-user-isolation-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "service-specific-credential-cross-user-isolation-rejected"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Update/Reset/DeleteServiceSpecificCredential naming another user's name are rejected with
    ValidationError and leave the credential intact, while the owner's own calls succeed."""
    iam = ctx.client("iam")
    owner_name = ctx.unique_name("sim2real-behav-sscowner-")
    other_name = ctx.unique_name("sim2real-behav-sscother-")
    service_name = "codecommit.amazonaws.com"

    iam.create_user(UserName=owner_name, Tags=[{"Key": "env", "Value": "sdk-test"}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=owner_name))
    iam.create_user(UserName=other_name, Tags=[{"Key": "env", "Value": "sdk-test"}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=other_name))

    created = iam.create_service_specific_credential(UserName=owner_name, ServiceName=service_name)[
        "ServiceSpecificCredential"
    ]
    cred_id = created["ServiceSpecificCredentialId"]
    initial_password = created["ServicePassword"]
    ctx.on_cleanup(
        lambda: _ignore_no_such_entity(
            lambda: iam.delete_service_specific_credential(
                UserName=owner_name, ServiceSpecificCredentialId=cred_id
            )
        )
    )

    # A new credential is eventually consistent; wait until the owner's listing shows it.
    _wait_for_credential_active(iam, owner_name, cred_id)

    # Positive control: the owner's own Update/Reset/Delete must succeed.
    iam.update_service_specific_credential(
        UserName=owner_name, ServiceSpecificCredentialId=cred_id, Status="Inactive"
    )
    owner_creds = iam.list_service_specific_credentials(UserName=owner_name)["ServiceSpecificCredentials"]
    assert any(
        c["ServiceSpecificCredentialId"] == cred_id and c["Status"] == "Inactive" for c in owner_creds
    ), "owner's own UpdateServiceSpecificCredential to Inactive must take effect"
    iam.update_service_specific_credential(
        UserName=owner_name, ServiceSpecificCredentialId=cred_id, Status="Active"
    )
    owner_creds = iam.list_service_specific_credentials(UserName=owner_name)["ServiceSpecificCredentials"]
    assert any(
        c["ServiceSpecificCredentialId"] == cred_id and c["Status"] == "Active" for c in owner_creds
    ), "owner's own UpdateServiceSpecificCredential back to Active must take effect"

    reset = iam.reset_service_specific_credential(
        UserName=owner_name, ServiceSpecificCredentialId=cred_id
    )["ServiceSpecificCredential"]
    assert reset["ServiceSpecificCredentialId"] == cred_id
    assert reset["ServicePassword"] != initial_password, (
        "owner's own ResetServiceSpecificCredential must actually rotate the secret"
    )

    second = iam.create_service_specific_credential(UserName=owner_name, ServiceName=service_name)[
        "ServiceSpecificCredential"
    ]
    second_id = second["ServiceSpecificCredentialId"]
    ctx.on_cleanup(
        lambda: _ignore_no_such_entity(
            lambda: iam.delete_service_specific_credential(
                UserName=owner_name, ServiceSpecificCredentialId=second_id
            )
        )
    )
    _wait_for_credential_active(iam, owner_name, second_id)
    iam.delete_service_specific_credential(UserName=owner_name, ServiceSpecificCredentialId=second_id)
    owner_creds = iam.list_service_specific_credentials(UserName=owner_name)["ServiceSpecificCredentials"]
    assert all(c["ServiceSpecificCredentialId"] != second_id for c in owner_creds), (
        "owner's own DeleteServiceSpecificCredential must actually remove the credential"
    )
    assert any(c["ServiceSpecificCredentialId"] == cred_id and c["Status"] == "Active" for c in owner_creds)

    # The ownership index these calls consult can lag the listing, so poll for the rejection;
    # retrying is safe because a rejected call has no effect.
    mismatch = (
        "ValidationError",
        f"User {other_name} does not have a service specific credential with id {cred_id}",
    )
    _assert_eventually_rejected(
        lambda: iam.update_service_specific_credential(
            UserName=other_name, ServiceSpecificCredentialId=cred_id, Status="Inactive"
        ),
        expected=mismatch,
    )
    _assert_eventually_rejected(
        lambda: iam.reset_service_specific_credential(
            UserName=other_name, ServiceSpecificCredentialId=cred_id
        ),
        expected=mismatch,
    )
    _assert_eventually_rejected(
        lambda: iam.delete_service_specific_credential(
            UserName=other_name, ServiceSpecificCredentialId=cred_id
        ),
        expected=mismatch,
    )

    # the credential must be untouched and still owned by the original user
    creds = iam.list_service_specific_credentials(UserName=owner_name)["ServiceSpecificCredentials"]
    assert any(c["ServiceSpecificCredentialId"] == cred_id and c["Status"] == "Active" for c in creds)


def _error(fn):
    """(code, message) of the refused call; an unexpected success is a failure."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _ignore_no_such_entity(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _wait_for_credential_active(iam, user_name, cred_id, timeout_s=30.0, interval_s=1.5):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        creds = iam.list_service_specific_credentials(UserName=user_name)["ServiceSpecificCredentials"]
        if any(c["ServiceSpecificCredentialId"] == cred_id and c["Status"] == "Active" for c in creds):
            return
        time.sleep(interval_s)
    raise AssertionError(f"service-specific credential {cred_id} never became visible/active for {user_name}")


def _assert_eventually_rejected(fn, expected, timeout_s=30.0, interval_s=2.0):
    """Poll until fn() is rejected with exactly `expected`; any success fails at once.

    The ownership check can briefly lag the credential's visibility in the listing.
    """
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _error(fn)
        if last == expected:
            return
        time.sleep(interval_s)
    raise AssertionError(f"expected rejection {expected!r}, got {last!r} after {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

