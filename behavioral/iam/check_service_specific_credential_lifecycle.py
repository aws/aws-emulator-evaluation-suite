"""service-specific-credential-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "service-specific-credential-lifecycle"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Service-specific credential create->active->status-updated->secret-reset->deleted transitions."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-behav-ssc-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    service_name = "codecommit.amazonaws.com"
    created = iam.create_service_specific_credential(UserName=user_name, ServiceName=service_name)[
        "ServiceSpecificCredential"
    ]
    cred_id = created["ServiceSpecificCredentialId"]
    original_password = created["ServicePassword"]
    assert created["Status"] == "Active", f"expected a freshly created credential to be Active, got {created['Status']!r}"
    assert created["ServiceName"] == service_name, f"expected ServiceName {service_name!r}, got {created['ServiceName']!r}"
    ctx.on_cleanup(
        lambda: _ignore_no_such_entity(
            lambda: iam.delete_service_specific_credential(
                UserName=user_name, ServiceSpecificCredentialId=cred_id
            )
        )
    )

    creds = {
        c["ServiceSpecificCredentialId"]: c
        for c in iam.list_service_specific_credentials(UserName=user_name)["ServiceSpecificCredentials"]
    }
    assert cred_id in creds, f"expected {cred_id!r} in the user's credential list, got {sorted(creds)!r}"
    assert creds[cred_id]["Status"] == "Active", f"expected Active in the independent list read, got {creds[cred_id]['Status']!r}"

    iam.update_service_specific_credential(
        UserName=user_name, ServiceSpecificCredentialId=cred_id, Status="Inactive"
    )
    creds = {
        c["ServiceSpecificCredentialId"]: c
        for c in iam.list_service_specific_credentials(UserName=user_name)["ServiceSpecificCredentials"]
    }
    assert creds[cred_id]["Status"] == "Inactive", f"expected Inactive after UpdateServiceSpecificCredential, got {creds[cred_id]['Status']!r}"

    reset = iam.reset_service_specific_credential(UserName=user_name, ServiceSpecificCredentialId=cred_id)[
        "ServiceSpecificCredential"
    ]
    assert reset["ServiceSpecificCredentialId"] == cred_id, f"expected reset to echo {cred_id!r}, got {reset['ServiceSpecificCredentialId']!r}"
    assert reset["ServicePassword"] != original_password, "expected ResetServiceSpecificCredential to rotate ServicePassword, but it matched the original"

    iam.delete_service_specific_credential(UserName=user_name, ServiceSpecificCredentialId=cred_id)

    creds_after = {
        c["ServiceSpecificCredentialId"]
        for c in iam.list_service_specific_credentials(UserName=user_name)["ServiceSpecificCredentials"]
    }
    assert cred_id not in creds_after, f"expected {cred_id!r} gone from the independent list read after delete, still present in {sorted(creds_after)!r}"

    _assert_not_found(
        lambda: iam.update_service_specific_credential(
            UserName=user_name, ServiceSpecificCredentialId=cred_id, Status="Inactive"
        ),
        cred_id,
    )


def _ignore_no_such_entity(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _assert_not_found(fn, cred_id):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "NoSuchEntity", f"expected NoSuchEntity mutating the deleted credential {cred_id!r}, got {code!r}"
        msg = exc.response["Error"].get("Message")
        want = f"No such credential {cred_id} exists"
        assert msg == want, f"NoSuchEntity message: wanted {want!r}, got {msg!r}"
    else:
        raise AssertionError(f"expected mutating the deleted credential {cred_id!r} to fail, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
