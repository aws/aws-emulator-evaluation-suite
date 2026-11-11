"""disassociate-source-not-associated-fails."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "disassociate-source-not-associated-fails"
GROUP = "overly-permissive"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DisassociateSourceFromS3TableIntegration on an identifier that was never
    associated (via AssociateSourceToS3TableIntegration) fails with
    ResourceNotFoundException rather than silently succeeding."""
    logs = ctx.client("logs")
    bogus_identifier = ctx.unique_name("sim2real-behav-s3table-src-")

    code, message = _error(
        lambda: logs.disassociate_source_from_s3_table_integration(identifier=bogus_identifier)
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException disassociating a never-associated source, got {code}"
    )
    assert message == f"Association not found for identifier: {bogus_identifier}", (
        f"unexpected message disassociating a never-associated source: {message!r}"
    )


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"expected disassociating a never-associated source to be rejected, but it "
        f"succeeded: {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
