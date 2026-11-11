"""certificate-authority-unknown-not-found."""
from __future__ import annotations

from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "certificate-authority-unknown-not-found"
GROUP = "error-semantics"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeCertificateAuthority/ListCertificateAuthorities against a cluster that
    does not exist return ResourceNotFoundException, not a generic failure -- and the
    same client still works fine against a cluster that does exist (ListClusters)."""
    eks = ctx.client("eks")

    bogus_cluster = ctx.unique_name("sim2real-nope-cluster-")
    bogus_ca_id = "00000000-0000-0000-0000-000000000000"

    expected_message = f"No cluster found for name: {bogus_cluster}."

    describe_code, describe_msg = _expect_error(
        lambda: eks.describe_certificate_authority(
            clusterName=bogus_cluster, certificateAuthorityId=bogus_ca_id
        )
    )
    assert describe_code == "ResourceNotFoundException", describe_code
    assert describe_msg == expected_message, describe_msg

    list_code, list_msg = _expect_error(
        lambda: eks.list_certificate_authorities(clusterName=bogus_cluster)
    )
    assert list_code == "ResourceNotFoundException", list_code
    assert list_msg == expected_message, list_msg

    # positive control: the eks control plane itself is reachable and functioning
    resp = eks.list_clusters()
    assert "clusters" in resp


def _expect_error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn, require that it raises ClientError, return (Code, Message)."""
    try:
        fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code", ""), error.get("Message", "")
    raise AssertionError("expected the call to fail, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
