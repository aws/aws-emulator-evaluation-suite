"""create-connector-invalid-certificate-authority-arn-pattern-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "create-connector-invalid-certificate-authority-arn-pattern-rejected"
GROUP = "validation"
SERVICES = ["pca-connector-ad"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateConnector rejects a CertificateAuthorityArn that fails the acm-pca ARN pattern with
    ValidationException and its exact message, while a pattern-valid CA ARN gets the exact
    DirectoryRegistration ResourceNotFoundException; neither creates a connector."""
    pcad = ctx.client("pca-connector-ad")
    account = ctx.client("sts").get_caller_identity()["Account"]

    directory_id = "d-1234567890"
    sg_ids = ["sg-0123456789abcdef0"]

    # positive control: pattern-valid ARN, same otherwise-fake DirectoryId/SecurityGroupIds,
    # clears the pattern check and is refused for the unregistered directory instead.
    valid_pattern_arn = (
        f"arn:aws:acm-pca:{ctx.region}:{account}:certificate-authority/{uuid.uuid4()}"
    )
    control_code, control_message = _error(
        lambda: pcad.create_connector(
            DirectoryId=directory_id,
            CertificateAuthorityArn=valid_pattern_arn,
            VpcInformation={"SecurityGroupIds": sg_ids},
            Tags={"sim2real": "pca-connector-ad"},
        )
    )
    assert control_code == "ResourceNotFoundException", (
        f"pattern-valid ARN must clear the pattern check, got {control_code!r}"
    )
    assert control_message == f"DirectoryRegistration was not found: {directory_id}.", (
        control_message
    )

    created = _connectors_with_ca(pcad, {valid_pattern_arn})
    assert created == [], f"positive control must not create a connector, found {created!r}"

    code, message = _error(
        lambda: pcad.create_connector(
            DirectoryId=directory_id,
            CertificateAuthorityArn="not-an-acm-pca-arn",
            VpcInformation={"SecurityGroupIds": sg_ids},
        )
    )
    assert code == "ValidationException", code
    assert message == (
        '[ECMA 262 regex "^arn:[\\w-]+:acm-pca:[\\w-]+:[0-9]+:certificate-authority'
        '\\/[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$" does not match input string '
        '"not-an-acm-pca-arn"]'
    ), message

    created = _connectors_with_ca(pcad, {valid_pattern_arn, "not-an-acm-pca-arn"})
    assert created == [], f"malformed-pattern call must not create a connector, found {created!r}"


def _connectors_with_ca(pcad, ca_arns) -> list:
    """Every listed connector, across all pages, whose CertificateAuthorityArn is one of ca_arns."""
    found, token = [], None
    while True:
        page = pcad.list_connectors(**({"NextToken": token} if token else {}))
        found += [c for c in page["Connectors"] if c.get("CertificateAuthorityArn") in ca_arns]
        token = page.get("NextToken")
        if not token:
            return found


def _error(fn):
    """Call fn(); return its error (code, message). A success raises, because a target that
    accepts what AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        resp = getattr(exc, "response", None)
        if resp:
            err = resp.get("Error", {})
            return err.get("Code"), err.get("Message")
        return type(exc).__name__, str(exc)
    raise AssertionError(f"expected a rejection, but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
