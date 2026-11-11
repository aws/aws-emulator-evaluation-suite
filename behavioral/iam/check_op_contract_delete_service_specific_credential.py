"""op-contract-deleteServiceSpecificCredential."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-deleteServiceSpecificCredential"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteServiceSpecificCredential removes the credential; deleting it again is rejected."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-behav-user-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    created = iam.create_service_specific_credential(UserName=user_name, ServiceName="codecommit.amazonaws.com")
    cred_id = created["ServiceSpecificCredential"]["ServiceSpecificCredentialId"]
    status = created["ServiceSpecificCredential"]["Status"]
    assert status == "Active", f"expected freshly created credential to be Active, got {status!r}"

    listed = iam.list_service_specific_credentials(UserName=user_name, ServiceName="codecommit.amazonaws.com")
    ids_before = {c["ServiceSpecificCredentialId"] for c in listed["ServiceSpecificCredentials"]}
    assert cred_id in ids_before, f"expected {cred_id} in {ids_before} right after creation"

    # success path
    resp = iam.delete_service_specific_credential(UserName=user_name, ServiceSpecificCredentialId=cred_id)
    status_code = resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status_code == 200, f"expected 200 from delete, got {status_code}"

    listed_after = iam.list_service_specific_credentials(UserName=user_name, ServiceName="codecommit.amazonaws.com")
    ids_after = {c["ServiceSpecificCredentialId"] for c in listed_after["ServiceSpecificCredentials"]}
    assert cred_id not in ids_after, "credential still listed after deletion"

    # error boundary: deleting the same (now nonexistent) credential id is rejected
    code, message = _error(
        lambda: iam.delete_service_specific_credential(UserName=user_name, ServiceSpecificCredentialId=cred_id)
    )
    # IAM's error Code is the bare name ("NoSuchEntity"), not the botocore exception
    # class name ("NoSuchEntityException").
    assert code == "NoSuchEntity", f"expected NoSuchEntity on redelete, got {code}"
    expected = f"No such credential {cred_id} exists"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its error (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
