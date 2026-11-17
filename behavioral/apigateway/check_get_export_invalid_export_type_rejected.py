"""get-export-invalid-export-type-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-export-invalid-export-type-rejected"
GROUP = "export"
SERVICES = ["apigateway"]

_BOGUS_EXPORT_TYPE = "sim2real-bogus"
_X = ("BadRequestException", f"No API exporter for type '{_BOGUS_EXPORT_TYPE}'")


def _delete_rest_api_quota_aware(apigw, api_id, *, budget_s: float = 320.0) -> None:
    """DeleteRestApi is quota'd to one call every 30s per account; retry the throttle."""
    deadline = time.monotonic() + budget_s
    delay = 5.0
    while True:
        try:
            apigw.delete_rest_api(restApiId=api_id)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NotFoundException":
                return
            if code != "TooManyRequestsException" or time.monotonic() >= deadline:
                raise
        time.sleep(delay)
        delay = min(delay * 2, 30.0)


def expect_error(fn, code, message):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        got = (err.get("Code"), err.get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected the call to be rejected with {(code, message)!r}, but it SUCCEEDED: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetExport rejects an exportType outside {oas30, swagger} with BadRequestException, while
    the identical call with a valid exportType on the same stage succeeds."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-behav-exportbad-"))["id"]
    ctx.on_cleanup(lambda: _delete_rest_api_quota_aware(apigw, api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]

    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")

    stage_name = "test"
    apigw.create_deployment(restApiId=api_id, stageName=stage_name)

    # positive control: the same stage exports fine under a valid exportType
    ok = apigw.get_export(restApiId=api_id, stageName=stage_name, exportType="oas30", accepts="application/json")
    ok_doc = json.loads(ok["body"].read())
    assert ok_doc.get("openapi") == "3.0.1", f"expected a valid oas30 export, got {ok_doc.get('openapi')!r}"

    expect_error(
        lambda: apigw.get_export(
            restApiId=api_id, stageName=stage_name, exportType=_BOGUS_EXPORT_TYPE,
            accepts="application/json",
        ),
        *_X,
    )

    # restore: the identical valid call still succeeds afterward
    again = apigw.get_export(restApiId=api_id, stageName=stage_name, exportType="oas30", accepts="application/json")
    again_doc = json.loads(again["body"].read())
    assert again_doc.get("openapi") == "3.0.1", (
        f"expected the valid export to keep succeeding after the rejected call, got "
        f"{again_doc.get('openapi')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
