"""create-model-invalid-content-type-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-model-invalid-content-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateModel rejects an empty/malformed contentType, a required field."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-apigw-"),
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    bad_name = "BadModel"
    # Negative: contentType is required but an empty string is not a valid media type.
    code, message = _error(
        lambda: apigw.create_model(
            restApiId=api_id,
            name=bad_name,
            contentType="",
            schema='{"type":"object"}',
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == "Invalid content type specified: ", f"unexpected BadRequestException message {message!r}"

    # Effect absent: the model must not have been created.
    absent_code, absent_message = _error(lambda: apigw.get_model(restApiId=api_id, modelName=bad_name))
    assert absent_code == "NotFoundException", f"model leaked despite empty contentType: {absent_code}"
    assert absent_message == f"Invalid model name specified: {bad_name}", f"unexpected NotFoundException message {absent_message!r}"

    # Positive control: a well-formed contentType succeeds.
    good_name = "GoodModel"
    apigw.create_model(
        restApiId=api_id,
        name=good_name,
        contentType="application/json",
        schema='{"type":"object"}',
    )
    model = apigw.get_model(restApiId=api_id, modelName=good_name)
    assert model["contentType"] == "application/json", (
        f"expected contentType application/json, got {model['contentType']!r}"
    )


def _error(fn):
    """Call fn(); return (code, message) of the refusal. A call that succeeds fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
