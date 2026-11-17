"""create-repository-kms-key-with-aes256-encryption-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _error(fn):
    """Return the botocore error (code, message) from fn(); raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


CHECK = "create-repository-kms-key-with-aes256-encryption-rejected"
GROUP = 'overly-permissive'
SERVICES = ['ecr']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateRepository with a kmsKey alongside AES256 encryption is rejected with
    InvalidParameterException and creates nothing; the same alias with KMS encryption succeeds."""
    ecr = ctx.client("ecr")
    bad_name = ctx.unique_name("sim2real-behav-ecr-repo-")

    expected = (
        "Invalid parameter at 'encryptionConfiguration' failed to satisfy constraint: "
        "'Invalid encryption configuration: Encryption key should not be set for AES256 "
        "encryption.'"
    )
    code, message = _error(
        lambda: ecr.create_repository(
            repositoryName=bad_name,
            encryptionConfiguration={"encryptionType": "AES256", "kmsKey": "alias/aws/ecr"},
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}: {message!r}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    nf_code, nf_message = _error(lambda: ecr.describe_repositories(repositoryNames=[bad_name]))
    assert nf_code == "RepositoryNotFoundException", (
        f"rejected repository appears to exist; describe returned {nf_code}"
    )

    good_name = ctx.unique_name("sim2real-behav-ecr-repo-")
    created = ecr.create_repository(
        repositoryName=good_name,
        encryptionConfiguration={"encryptionType": "KMS", "kmsKey": "alias/aws/ecr"},
    )
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=good_name, force=True))
    assert created["repository"]["encryptionConfiguration"]["encryptionType"] == "KMS", created


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
