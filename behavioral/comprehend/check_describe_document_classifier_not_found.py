"""describe-document-classifier-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-document-classifier-not-found"
GROUP = "error-semantics"
SERVICES = ["comprehend"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeDocumentClassifier rejects a syntactically valid but nonexistent
    DocumentClassifierArn with ResourceNotFoundException."""
    comprehend = ctx.client("comprehend")
    account_id = _account_id(ctx)
    fake_arn = (
        f"arn:aws:comprehend:{ctx.region}:{account_id}:"
        f"document-classifier/{ctx.unique_name('sim2real-nonexistent-classifier-')}"
    )

    code, message = _error(
        lambda: comprehend.describe_document_classifier(DocumentClassifierArn=fake_arn)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = "RESOURCE_NOT_FOUND: Could not find specified resource."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(), which must fail; return its botocore error (code, message). An unexpected
    SUCCESS raises, so a target that accepts what AWS refuses is never read as a mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
