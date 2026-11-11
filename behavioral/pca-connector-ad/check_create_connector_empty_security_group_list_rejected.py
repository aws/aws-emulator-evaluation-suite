"""create-connector-empty-security-group-list-rejected."""
from __future__ import annotations

import uuid

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-connector-empty-security-group-list-rejected"
GROUP = "overly-permissive"
SERVICES = ["pca-connector-ad"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateConnector with an empty VpcInformation.SecurityGroupIds (sent with client-side validation
    off) gets ValidationException with its exact message and creates no connector; ListConnectors
    succeeds for the same caller."""
    pcad = ctx.client("pca-connector-ad")
    account = ctx.client("sts").get_caller_identity()["Account"]
    ca_arn = f"arn:aws:acm-pca:{ctx.region}:{account}:certificate-authority/{uuid.uuid4()}"

    unvalidated = ctx.client("pca-connector-ad", config=Config(parameter_validation=False))
    code, message = _client_error(
        lambda: unvalidated.create_connector(
            DirectoryId="d-1234567890",
            CertificateAuthorityArn=ca_arn,
            VpcInformation={"SecurityGroupIds": []},
        )
    )
    assert code == "ValidationException", (
        f"expected a server-side ValidationException for an empty SecurityGroupIds list, got {code!r}"
    )
    assert message == (
        "[array is too short: must have at least 1 elements but instance has 0 elements]"
    ), message

    created = _connectors_with_ca(pcad, {ca_arn})
    assert created == [], f"no connector must have been created, found {created!r}"

    control = pcad.list_connectors()
    assert "Connectors" in control


def _connectors_with_ca(pcad, ca_arns) -> list:
    """Every listed connector, across all pages, whose CertificateAuthorityArn is one of ca_arns."""
    found, token = [], None
    while True:
        page = pcad.list_connectors(**({"NextToken": token} if token else {}))
        found += [c for c in page["Connectors"] if c.get("CertificateAuthorityArn") in ca_arns]
        token = page.get("NextToken")
        if not token:
            return found


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
