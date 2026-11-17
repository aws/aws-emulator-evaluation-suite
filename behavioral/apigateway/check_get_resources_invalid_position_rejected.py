"""get-resources-invalid-position-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-resources-invalid-position-rejected"
GROUP = "pagination"
SERVICES = ["apigateway"]
_INVALID_POSITION = ("BadRequestException", "Invalid position parameter")


def _teardown(undo, *not_found: str):
    """Cleanup running undo(); only the resource's own not_found codes mean it is gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    got_code, got_message = _error(fn)
    assert got_code == code, f"expected {code}, got {got_code}: {got_message!r}"
    assert got_message == message, f"expected message {message!r}, got {got_message!r}"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetResources with an unparseable `position` continuation value is refused with a 400
    BadRequestException; the same restApiId without it lists only its root resource and no
    `position`, including under a limit far larger than the one item it holds."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-res-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(_teardown(lambda: apigw.delete_rest_api(restApiId=api_id), "NotFoundException"))

    expect_error(
        lambda: apigw.get_resources(restApiId=api_id, position="not-a-real-pagination-token"),
        *_INVALID_POSITION,
    )

    # Positive control: the same API, without the malformed position, still lists only its root.
    control = apigw.get_resources(restApiId=api_id)
    assert len(control["items"]) == 1, f"expected exactly 1 item (the root), got {control['items']!r}"
    assert control["items"][0]["path"] == "/", f"expected root path '/', got {control['items'][0]['path']!r}"
    assert "position" not in control, f"a single-item listing still carried a position: {control!r}"

    oversized = apigw.get_resources(restApiId=api_id, limit=500)
    assert len(oversized["items"]) == 1, (
        f"expected exactly 1 item under limit=500, got {oversized['items']!r}"
    )
    assert "position" not in oversized, (
        f"a limit (500) larger than the 1 resource present still carried a position: {oversized!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
