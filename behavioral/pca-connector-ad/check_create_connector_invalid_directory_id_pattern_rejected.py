"""create-connector-invalid-directory-id-pattern-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "create-connector-invalid-directory-id-pattern-rejected"
GROUP = "validation"
SERVICES = ["pca-connector-ad"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateConnector rejects a DirectoryId that fails ^d-[0-9a-f]{10}$ with ValidationException and
    its exact message, while a pattern-valid unregistered DirectoryId gets the exact
    DirectoryRegistration ResourceNotFoundException; neither creates a connector."""
    pcad = ctx.client("pca-connector-ad")
    account = ctx.client("sts").get_caller_identity()["Account"]
    ca_arn = (
        f"arn:aws:acm-pca:{ctx.region}:{account}:certificate-authority/{uuid.uuid4()}"
    )

    code, message = _error(
        lambda: pcad.create_connector(
            DirectoryId="not-a-valid-directory-id",
            CertificateAuthorityArn=ca_arn,
            VpcInformation={"SecurityGroupIds": ["sg-0123456789abcdef0"]},
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == (
        '[ECMA 262 regex "^d-[0-9a-f]{10}$" does not match input string '
        '"not-a-valid-directory-id"]'
    ), message

    created = _connectors_with_ca(pcad, {ca_arn})
    assert created == [], f"no connector must have been created, found {created!r}"

    # positive control: an otherwise-identical call with a pattern-valid DirectoryId (for a
    # directory that is not registered) clears the pattern check and is refused as not found --
    # proving the rejection above is specific to the malformed pattern, not every CreateConnector call.
    control_code, control_message = _error(
        lambda: pcad.create_connector(
            DirectoryId="d-1234567890",
            CertificateAuthorityArn=ca_arn,
            VpcInformation={"SecurityGroupIds": ["sg-0123456789abcdef0"]},
        )
    )
    assert control_code == "ResourceNotFoundException", (
        f"pattern-valid DirectoryId must clear the pattern check, got {control_code!r}"
    )
    assert control_message == "DirectoryRegistration was not found: d-1234567890.", (
        control_message
    )

    # terminal independent read: the refused control created no connector either.
    created = _connectors_with_ca(pcad, {ca_arn})
    assert created == [], f"control failure must not have created a connector either, found {created!r}"


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
