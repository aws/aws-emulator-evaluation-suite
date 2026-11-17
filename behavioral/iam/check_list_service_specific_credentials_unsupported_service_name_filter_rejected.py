"""list-service-specific-credentials-unsupported-service-name-filter-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-service-specific-credentials-unsupported-service-name-filter-rejected"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListServiceSpecificCredentials rejects a ServiceName filter for a service that does not
    support service-specific credentials with NoSuchEntity, while a supported ServiceName narrows
    the result to exactly that service's credentials."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-behav-sscfilter-")
    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    codecommit_cred = iam.create_service_specific_credential(
        UserName=user_name, ServiceName="codecommit.amazonaws.com"
    )["ServiceSpecificCredential"]
    codecommit_id = codecommit_cred["ServiceSpecificCredentialId"]
    ctx.on_cleanup(
        lambda: iam.delete_service_specific_credential(
            UserName=user_name, ServiceSpecificCredentialId=codecommit_id
        )
    )

    bedrock_cred = iam.create_service_specific_credential(
        UserName=user_name, ServiceName="bedrock.amazonaws.com", CredentialAgeDays=30
    )["ServiceSpecificCredential"]
    bedrock_id = bedrock_cred["ServiceSpecificCredentialId"]
    ctx.on_cleanup(
        lambda: iam.delete_service_specific_credential(
            UserName=user_name, ServiceSpecificCredentialId=bedrock_id
        )
    )

    # positive control: a supported ServiceName narrows to exactly that service's credential.
    by_codecommit = {
        c["ServiceSpecificCredentialId"]
        for c in iam.list_service_specific_credentials(
            UserName=user_name, ServiceName="codecommit.amazonaws.com"
        )["ServiceSpecificCredentials"]
    }
    assert by_codecommit == {codecommit_id}, (
        f"filtering by codecommit.amazonaws.com should return exactly {{{codecommit_id!r}}}, got {by_codecommit!r}"
    )
    by_bedrock = {
        c["ServiceSpecificCredentialId"]
        for c in iam.list_service_specific_credentials(
            UserName=user_name, ServiceName="bedrock.amazonaws.com"
        )["ServiceSpecificCredentials"]
    }
    assert by_bedrock == {bedrock_id}, (
        f"filtering by bedrock.amazonaws.com should return exactly {{{bedrock_id!r}}}, got {by_bedrock!r}"
    )

    # omitting ServiceName returns every credential regardless of service.
    both = {
        c["ServiceSpecificCredentialId"]
        for c in iam.list_service_specific_credentials(UserName=user_name)["ServiceSpecificCredentials"]
    }
    assert both == {codecommit_id, bedrock_id}, (
        f"omitting ServiceName should return both credentials {{{codecommit_id!r}, {bedrock_id!r}}}, got {both!r}"
    )

    # a ServiceName filter for a recognized but unsupported service is rejected outright, not
    # treated as a filter that simply matches nothing.
    code, message = _error(
        lambda: iam.list_service_specific_credentials(UserName=user_name, ServiceName="glue.amazonaws.com")
    )
    assert code == "NoSuchEntity", f"expected NoSuchEntity filtering by an unsupported service, got {code!r}"
    expected_message = "No such service glue.amazonaws.com is supported for Service Specific Credentials"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
