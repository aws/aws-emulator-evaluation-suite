"""create-documentation-version-nonexistent-stage-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-documentation-version-nonexistent-stage-rejected"
GROUP = "documentation"
SERVICES = ["apigateway"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDocumentationVersion rejects a stageName that names no stage on the API and creates
    no version, while the identical call naming a real, deployed stage succeeds."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-docver-"), tags={"sim2real": CHECK})["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = next(r["id"] for r in apigw.get_resources(restApiId=api_id)["items"] if r["path"] == "/")

    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.create_documentation_part(
        restApiId=api_id, location={"type": "API"}, properties=json.dumps({"description": "v1"})
    )

    stage_name = "sim2real-live"
    apigw.create_deployment(restApiId=api_id, stageName=stage_name)

    control = apigw.create_documentation_version(
        restApiId=api_id, documentationVersion="1.0.0", stageName=stage_name,
    )
    assert control["version"] == "1.0.0", (
        f"positive control: expected version '1.0.0' echoed, got {control.get('version')!r}"
    )

    code, message = _error(lambda: apigw.create_documentation_version(
        restApiId=api_id, documentationVersion="2.0.0", stageName="sim2real-no-such-stage",
    ))
    assert code == "BadRequestException", (
        f"expected BadRequestException for a stageName naming no stage, got {code!r}"
    )
    expected_message = "Invalid stage identifier specified"
    assert message == expected_message, f"unexpected BadRequestException message {message!r}"

    versions = {v["version"] for v in apigw.get_documentation_versions(restApiId=api_id)["items"]}
    assert "2.0.0" not in versions, f"the rejected call created version 2.0.0 anyway: {versions!r}"
    assert versions == {"1.0.0"}, f"expected only the positive control's version, got {versions!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
