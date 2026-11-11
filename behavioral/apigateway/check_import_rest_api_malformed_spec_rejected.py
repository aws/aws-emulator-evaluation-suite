"""import-rest-api-malformed-spec-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "import-rest-api-malformed-spec-rejected"
GROUP = 'overly-permissive'
SERVICES = ['apigateway']


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"the call was expected to be REJECTED but it succeeded, returning {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ImportRestApi rejects a malformed OpenAPI document with BadRequestException and creates no
    RestApi, while a well-formed document imports first (positive control)."""
    ag = ctx.client("apigateway")

    # Positive control: a well-formed document imports and is independently readable.
    control_title = ctx.unique_name("sim2real-behav-apigw-malformed-spec-control-")
    control_doc = {
        "swagger": "2.0",
        "info": {"title": control_title, "version": "1.0"},
        "paths": {
            "/hello": {
                "get": {
                    "responses": {"200": {"description": "ok"}},
                    "x-amazon-apigateway-integration": {
                        "type": "MOCK",
                        "requestTemplates": {"application/json": '{"statusCode": 200}'},
                        "responses": {"default": {"statusCode": "200"}},
                    },
                }
            }
        },
    }
    control_body = json.dumps(control_doc).encode()
    control = ag.import_rest_api(body=control_body)
    control_id = control["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=control_id))
    ag.tag_resource(
        resourceArn=f"arn:aws:apigateway:{ctx.region}::/restapis/{control_id}",
        tags={"sim2real": "import-malformed-spec-control"},
    )
    fetched = ag.get_rest_api(restApiId=control_id)
    assert fetched["name"] == control_title, (
        f"positive control: expected the imported API's name to be {control_title!r}, "
        f"got {fetched.get('name')!r}"
    )

    # a partial import would carry this run's unique title
    broken_title = ctx.unique_name("sim2real-behav-apigw-malformed-spec-broken-")
    malformed_body = b'{"openapi": "3.0.1", "info": {"title": "' + broken_title.encode() + b'" NOT VALID JSON !!!'
    code, message = _error(lambda: ag.import_rest_api(body=malformed_body))
    assert code == "BadRequestException", (
        f"expected BadRequestException importing a malformed OpenAPI document, got {code}"
    )
    assert message == "Invalid OAS input", f"unexpected rejection message {message!r}"

    after = [
        a for page in ag.get_paginator("get_rest_apis").paginate(PaginationConfig={"PageSize": 500})
        for a in page.get("items", [])
    ]
    assert control_id in {a["id"] for a in after}, "the control RestApi must still be listed"
    partial = [a["id"] for a in after if a["name"] == broken_title]
    assert partial == [], (
        f"a rejected ImportRestApi must not have created a partial/corrupt RestApi, found {partial!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
