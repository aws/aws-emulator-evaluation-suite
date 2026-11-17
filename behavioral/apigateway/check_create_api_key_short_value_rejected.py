"""create-api-key-short-value-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-api-key-short-value-rejected"
GROUP = "api-keys"
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
    """CreateApiKey rejects a customer-supplied value shorter than 20 characters and creates no
    key, while a 20-character value is accepted."""
    apigw = ctx.client("apigateway")

    control_name = ctx.unique_name("sim2real-key-ok-")
    control_value = f"sim2real{uuid.uuid4().hex}"[:20]
    assert len(control_value) == 20, f"test setup bug: control value length {len(control_value)}"

    control = apigw.create_api_key(name=control_name, value=control_value, enabled=True)
    control_id = control["id"]
    ctx.on_cleanup(lambda: apigw.delete_api_key(apiKey=control_id))
    assert control["value"] == control_value, (
        f"positive control: expected the 20-char value echoed, got {control['value']!r}"
    )

    rejected_name = ctx.unique_name("sim2real-key-bad-")
    rejected_value = f"sim2real{uuid.uuid4().hex}"[:19]
    assert len(rejected_value) == 19, f"test setup bug: rejected value length {len(rejected_value)}"

    code, message = _error(
        lambda: apigw.create_api_key(name=rejected_name, value=rejected_value, enabled=True)
    )
    assert code == "BadRequestException", (
        f"expected BadRequestException for a 19-character API key value, got {code!r}"
    )
    expected_message = "API Key value should be at least 20 characters"
    assert message == expected_message, f"unexpected BadRequestException message {message!r}"

    after_names = {k["name"] for k in apigw.get_paginator("get_api_keys").paginate().build_full_result()["items"]}
    assert rejected_name not in after_names, (
        f"the rejected call created a key named {rejected_name!r} anyway"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
