"""get-documentation-version-nonexistent-returns-notfound."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-documentation-version-nonexistent-returns-notfound"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDocumentationVersion returns the record for a created version "v1" (positive control)
    and fails with NotFoundException, not an empty object, for a version that does not exist."""
    apigw = ctx.client("apigateway")
    api = apigw.create_rest_api(name=ctx.unique_name("sim2real-docver-api-"))
    rest_api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=rest_api_id))

    code, message = _error(
        lambda: apigw.get_documentation_version(
            restApiId=rest_api_id, documentationVersion="v-does-not-exist"
        )
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == "Invalid Documentation version specified", f"unexpected NotFoundException message {message!r}"

    # CreateDocumentationVersion snapshots the API's documentation parts, so at least one
    # part must exist first or it's rejected with BadRequestException ("doesn't contain any
    # documentation parts") before the version-lookup behavior under test is ever exercised.
    apigw.create_documentation_part(
        restApiId=rest_api_id,
        location={"type": "API"},
        properties='{"description": "sim2real doc part"}',
    )

    # positive control: a real documentation version is retrievable by its exact version string
    apigw.create_documentation_version(
        restApiId=rest_api_id, documentationVersion="v1", description="sim2real v1"
    )
    got = apigw.get_documentation_version(restApiId=rest_api_id, documentationVersion="v1")
    assert got["version"] == "v1", f"expected version 'v1', got {got.get('version')!r}"
    assert got["description"] == "sim2real v1", (
        f"expected description 'sim2real v1', got {got.get('description')!r}"
    )

    # the unrelated nonexistent version string is still not found
    code2, message2 = _error(
        lambda: apigw.get_documentation_version(
            restApiId=rest_api_id, documentationVersion="v-does-not-exist"
        )
    )
    assert code2 == "NotFoundException", f"expected NotFoundException, got {code2}"
    assert message2 == "Invalid Documentation version specified", f"unexpected NotFoundException message {message2!r}"


def _error(fn):
    """Call fn(); return its botocore (error code, error message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available and must not be
    reported as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
