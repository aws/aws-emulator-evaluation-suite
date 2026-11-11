"""get-documentation-version-unauthorized-vs-notfound."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

CHECK = "get-documentation-version-unauthorized-vs-notfound"
GROUP = "error-semantics"
SERVICES = ["apigateway"]

from behavioral_harness import tags


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetDocumentationVersion returns a version that exists and raises NotFoundException for one
    never created, not a malformed-request code: its modeled errors omit BadRequestException."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-api-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_rest_api(restApiId=api_id)))

    # CreateDocumentationVersion snapshots the API's documentation parts, so at least one part
    # must exist first or the create itself is rejected with BadRequestException before the
    # version-lookup behavior under test is ever exercised.
    apigw.create_documentation_part(
        restApiId=api_id,
        location={"type": "API"},
        properties=json.dumps({"description": "sim2real doc part"}),
    )

    version_id = "v1"
    apigw.create_documentation_version(restApiId=api_id, documentationVersion=version_id)

    # Positive control: the version we actually created is fetchable through the same operation.
    control = apigw.get_documentation_version(restApiId=api_id, documentationVersion=version_id)
    assert control["version"] == version_id, (
        f"expected version {version_id!r}, got {control.get('version')!r}"
    )

    # A version that was never created raises the specific NotFoundException.
    code, message = _error(
        lambda: apigw.get_documentation_version(
            restApiId=api_id, documentationVersion="does-not-exist-v1"
        )
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == "Invalid Documentation version specified", f"unexpected NotFoundException message {message!r}"


def _error(fn):
    """Call fn(); return its botocore (error code, error message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available and must not be
    reported as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
