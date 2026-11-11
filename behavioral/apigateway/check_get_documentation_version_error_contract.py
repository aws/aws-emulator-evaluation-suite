"""get-documentation-version-error-contract."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-documentation-version-error-contract"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


def _error(fn):
    """Call fn(); return its botocore (error code, error message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects GetDocumentationVersion for a nonexistent version, but it "
        f"SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDocumentationVersion's error set omits BadRequestException; a nonexistent version
    identifier returns NotFoundException, and a valid one round-trips correctly."""
    apigw = ctx.client("apigateway")
    api = apigw.create_rest_api(name=ctx.unique_name("sim2real-behav-restapi-"))
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    apigw.create_documentation_part(
        restApiId=api_id,
        location={"type": "API"},
        properties='{"description": "test api"}',
    )
    apigw.create_documentation_version(restApiId=api_id, documentationVersion="v1")

    # positive round-trip
    got = apigw.get_documentation_version(restApiId=api_id, documentationVersion="v1")
    assert got["version"] == "v1", f"expected version 'v1', got {got.get('version')!r}"

    # negative: nonexistent version -> NotFoundException, never BadRequestException
    code, message = _error(
        lambda: apigw.get_documentation_version(
            restApiId=api_id, documentationVersion="does-not-exist-v999"
        )
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code!r}"
    assert message == "Invalid Documentation version specified", f"unexpected NotFoundException message {message!r}"
    assert code != "BadRequestException", (
        f"expected NotFoundException (not BadRequestException) for a nonexistent "
        f"documentation version, got {code!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
