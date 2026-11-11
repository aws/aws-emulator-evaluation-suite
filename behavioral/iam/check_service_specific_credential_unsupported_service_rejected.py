"""service-specific-credential-unsupported-service-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "service-specific-credential-unsupported-service-rejected"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateServiceSpecificCredential for iam.amazonaws.com, a recognized service without
    service-specific credentials, fails with NoSuchEntity and the exact message listing the supported
    services and creates nothing, while codecommit.amazonaws.com gets an Active, listed credential."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-behav-sscreject-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real-check", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    # IAM is eventually consistent: immediately after create_user, a dependent call
    # (create_service_specific_credential) can spuriously fail with NoSuchEntity
    # before the new user has propagated. Poll get_user until it succeeds so the
    # subsequent negative assertion is actually exercising ServiceName validation
    # rather than racing user-creation propagation.
    _poll_until(lambda: _user_exists(iam, user_name))

    # On real AWS, an unsupported-but-recognized ServiceName is rejected with a
    # NoSuchEntity error (not ServiceNotSupportedException, despite that shape existing in
    # the API model) whose message enumerates/names the rejected service. Capture the
    # full error so we can assert on both the code and that message content, which lets us
    # tell this "unsupported service" rejection apart from an unrelated "user not yet
    # visible to this backend" NoSuchEntity race.
    from botocore.exceptions import ClientError

    try:
        result = iam.create_service_specific_credential(
            UserName=user_name, ServiceName="iam.amazonaws.com"
        )
    except ClientError as err:
        code = err.response["Error"]["Code"]
        message = err.response["Error"].get("Message", "")
    else:
        raise AssertionError(f"expected the unsupported ServiceName to be rejected, got {result!r}")
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code}"
    want = "No such service iam.amazonaws.com is supported for Service Specific Credentials"
    assert message == want, f"expected the rejection message {want!r}, got: {message!r}"

    creds = iam.list_service_specific_credentials(UserName=user_name)["ServiceSpecificCredentials"]
    assert creds == [], "no credential should have been created for the unsupported service"

    # positive control: a supported service name succeeds.
    created = iam.create_service_specific_credential(
        UserName=user_name, ServiceName="codecommit.amazonaws.com"
    )["ServiceSpecificCredential"]
    cred_id = created["ServiceSpecificCredentialId"]
    assert created["Status"] == "Active", (
        f"expected the positive-control credential to be Active, got {created['Status']!r}"
    )
    ctx.on_cleanup(lambda: _safe_delete_credential(iam, user_name, cred_id))

    creds_after = [
        c["ServiceSpecificCredentialId"]
        for c in iam.list_service_specific_credentials(UserName=user_name)["ServiceSpecificCredentials"]
    ]
    assert cred_id in creds_after, (
        f"expected {cred_id} in ListServiceSpecificCredentials after the supported-service create, "
        f"got {creds_after}"
    )


def _poll_until(predicate, timeout_s=30.0, interval_s=1.0):
    import time

    deadline = time.monotonic() + timeout_s
    while True:
        if predicate():
            return
        if time.monotonic() >= deadline:
            raise TimeoutError("condition not met before timeout")
        time.sleep(interval_s)


def _user_exists(iam, user_name):
    from botocore.exceptions import ClientError

    try:
        iam.get_user(UserName=user_name)
        return True
    except ClientError as err:
        if err.response["Error"]["Code"] == "NoSuchEntity":
            return False
        raise


def _safe_delete_credential(iam, user_name, cred_id):
    from botocore.exceptions import ClientError

    try:
        iam.delete_service_specific_credential(
            UserName=user_name, ServiceSpecificCredentialId=cred_id
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
