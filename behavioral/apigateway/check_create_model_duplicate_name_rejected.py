"""create-model-duplicate-name-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-model-duplicate-name-rejected"
GROUP = "ordering"
SERVICES = ["apigateway"]

_SCHEMA = '{"$schema":"http://json-schema.org/draft-04/schema#","title":"Dup","type":"object"}'


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateModel rejects a second model with a name that already exists on the API with
    ConflictException, leaves the original model's schema untouched, while a differently
    named model on the same API still succeeds."""
    apigw = ctx.client("apigateway")

    api = apigw.create_rest_api(name=ctx.unique_name("sim2real-api-"), tags={"sim2real": CHECK})
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    name = "".join(ch for ch in ctx.unique_name("SimDupModel") if ch.isalnum())
    original_schema = _SCHEMA
    apigw.create_model(restApiId=api_id, name=name, contentType="application/json", schema=original_schema)

    conflicting_schema = (
        '{"$schema":"http://json-schema.org/draft-04/schema#","title":"Dup","type":"object",'
        '"properties":{"y":{"type":"string"}}}'
    )
    code, message = _error(
        lambda: apigw.create_model(
            restApiId=api_id, name=name, contentType="application/json", schema=conflicting_schema
        )
    )
    assert code == "ConflictException", f"expected ConflictException for duplicate model name, got {code}"
    assert message == "Model name already exists for this REST API", f"unexpected ConflictException message {message!r}"

    # The original model must be untouched by the rejected duplicate create.
    current = apigw.get_model(restApiId=api_id, modelName=name)
    assert current["schema"] == original_schema, "rejected duplicate create still mutated the existing model"

    # Positive control: a differently-named model on the same API still succeeds.
    other_name = "".join(ch for ch in ctx.unique_name("SimOtherModel") if ch.isalnum())
    created = apigw.create_model(restApiId=api_id, name=other_name, contentType="application/json", schema=_SCHEMA)
    assert created["name"] == other_name, f"expected create_model to echo name {other_name!r}, got {created.get('name')!r}"

    # Terminal read is independent of the mutating call: the positive-control model must be
    # visible, with its schema intact, via a separate get_model read.
    fetched_other = apigw.get_model(restApiId=api_id, modelName=other_name)
    assert fetched_other["schema"] == _SCHEMA, (
        f"positive-control model {other_name!r} not visible with its schema via independent get_model read"
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
