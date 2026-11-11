"""describe-certificate-authority-unknown-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-certificate-authority-unknown-not-found"
GROUP = "error-semantics"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeCertificateAuthority and DeleteCertificateAuthority for an unknown CA id on an unknown cluster
    both fail with ResourceNotFoundException and the same exact message.
    """
    eks = ctx.client("eks")
    fake_cluster = ctx.unique_name("sim2real-eks-nonexistent-")
    fake_ca_id = ctx.unique_name("sim2real-ca-")

    expected_message = f"No cluster found for name: {fake_cluster}."

    describe_code, describe_message = _error(
        lambda: eks.describe_certificate_authority(
            clusterName=fake_cluster, certificateAuthorityId=fake_ca_id
        )
    )
    assert describe_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from DescribeCertificateAuthority, got {describe_code!r}"
    )
    assert describe_message == expected_message, describe_message

    delete_code, delete_message = _error(
        lambda: eks.delete_certificate_authority(
            clusterName=fake_cluster, certificateAuthorityId=fake_ca_id
        )
    )
    assert delete_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from DeleteCertificateAuthority, got {delete_code!r}"
    )
    assert delete_message == expected_message, delete_message


def _error(fn):
    """Call fn, require it raises ClientError, return (Code, Message)."""
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError("expected the call to fail, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
