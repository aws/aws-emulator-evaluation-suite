"""op-contract-createServiceSpecificCredential."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-createServiceSpecificCredential"
GROUP = "error-semantics"
SERVICES = ["iam"]


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it must raise."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateServiceSpecificCredential mints an Active credential scoped to the requested
    service and user; requesting one for a nonexistent user is rejected with
    NoSuchEntityException and no credential is created."""
    iam = ctx.client("iam")
    user = ctx.unique_name("sim2real-behav-sscuser-")
    iam.create_user(
        UserName=user,
        Tags=[{"Key": "sim2real", "Value": "create-service-specific-credential-contract"}],
    )
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user))

    cred = iam.create_service_specific_credential(UserName=user, ServiceName="codecommit.amazonaws.com")[
        "ServiceSpecificCredential"
    ]
    cred_id = cred["ServiceSpecificCredentialId"]
    ctx.on_cleanup(
        lambda: iam.delete_service_specific_credential(
            UserName=user, ServiceSpecificCredentialId=cred_id
        )
    )
    assert cred["UserName"] == user, f"expected UserName {user!r}, got {cred['UserName']!r}"
    assert cred["ServiceName"] == "codecommit.amazonaws.com", cred["ServiceName"]
    assert cred["Status"] == "Active", f"expected Status Active, got {cred['Status']!r}"
    assert cred["ServiceUserName"], "generated login handle must be non-empty"
    assert cred["ServiceUserName"].startswith(user), (
        f"expected the generated login handle to derive from {user!r}, got {cred['ServiceUserName']!r}"
    )
    assert cred["ServicePassword"], "generated password must be non-empty"

    listed = iam.list_service_specific_credentials(UserName=user)["ServiceSpecificCredentials"]
    assert any(c["ServiceSpecificCredentialId"] == cred_id for c in listed), (
        f"expected {cred_id!r} in {[c['ServiceSpecificCredentialId'] for c in listed]!r}"
    )

    # Distinct error boundary: UserName does not exist -> NoSuchEntityException, and no
    # credential shows up for the (still-existing) real user as a side effect.
    bogus_user = ctx.unique_name("sim2real-behav-sscuser-missing-")
    code, message = _error(
        lambda: iam.create_service_specific_credential(
            UserName=bogus_user, ServiceName="codecommit.amazonaws.com"
        )
    )
    assert code == "NoSuchEntity", f"expected NoSuchEntity for a nonexistent user, got {code!r}"
    assert message == f"The user with name {bogus_user} cannot be found.", (
        f"CreateServiceSpecificCredential for a nonexistent user message: {message!r}"
    )

    listed_after = iam.list_service_specific_credentials(UserName=user)["ServiceSpecificCredentials"]
    assert len(listed_after) == 1, (
        f"expected exactly 1 credential still listed for {user!r}, got {len(listed_after)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
