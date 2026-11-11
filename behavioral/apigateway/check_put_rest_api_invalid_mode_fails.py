"""put-rest-api-invalid-mode-fails."""
from __future__ import annotations

import json
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "put-rest-api-invalid-mode-fails"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutRestApi with an unsupported `mode` value (only 'merge'/'overwrite' are
    valid) must fail with ValidationException instead of applying a partial or
    best-effort update to the API definition."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-api-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    # positive control: a supported mode must actually apply, so a target that
    # rejects every PutRestApi call cannot be confused with one that correctly
    # rejects only the unsupported mode value.
    control_path = "/control"
    control_body = json.dumps(
        {
            "swagger": "2.0",
            "info": {"title": "control", "version": "1.0"},
            "paths": {control_path: {"get": {"responses": {"200": {"description": "ok"}}}}},
        }
    ).encode("utf-8")
    apigw.put_rest_api(restApiId=api_id, mode="merge", body=control_body)
    control_resources = apigw.get_resources(restApiId=api_id)["items"]
    assert any(r.get("path") == control_path for r in control_resources), (
        f"positive control failed: PutRestApi(mode='merge') did not create {control_path!r} "
        f"among {[r.get('path') for r in control_resources]!r}; cannot distinguish 'rejects the "
        "invalid mode' from 'rejects every PutRestApi call'"
    )

    before = apigw.get_rest_api(restApiId=api_id)
    marker_title = ctx.unique_name("sim2real-marker-")
    body = json.dumps(
        {
            "swagger": "2.0",
            "info": {"title": marker_title, "version": "2.0"},
            "paths": {"/marked": {"get": {"responses": {"200": {"description": "ok"}}}}},
        }
    ).encode("utf-8")

    bad_mode = "sideways"
    code, message = _error(
        lambda: apigw.put_rest_api(restApiId=api_id, mode=bad_mode, body=body)
    )
    assert code == "ValidationException", (
        f"expected ValidationException for an unsupported PutRestApi mode, got {code!r}"
    )
    assert message == (
        f"1 validation error detected: Value '{bad_mode}' at 'mode' failed to satisfy "
        "constraint: Member must satisfy enum value set: [overwrite, merge]"
    ), f"unexpected message: {message!r}"

    # confirm no partial update was applied: name/version must be untouched
    after = apigw.get_rest_api(restApiId=api_id)
    assert after["name"] == before["name"], (
        f"PutRestApi with an invalid mode must not rename the API: "
        f"expected {before['name']!r}, got {after['name']!r}"
    )
    assert after.get("version") == before.get("version"), (
        f"PutRestApi with an invalid mode must not change the API version: "
        f"expected {before.get('version')!r}, got {after.get('version')!r}"
    )
    resources = apigw.get_resources(restApiId=api_id)["items"]
    assert all(r.get("path") != "/marked" for r in resources), (
        "PutRestApi with an invalid mode must not create resources from the rejected body"
    )


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"expected PutRestApi with an unsupported mode to be rejected, but it SUCCEEDED "
        f"and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
