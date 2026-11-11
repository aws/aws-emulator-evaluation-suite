"""get-rest-api-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-rest-api-not-found"
GROUP = 'overly-permissive'
SERVICES = ['apigateway']


def _error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"real AWS rejects GetRestApi on a bogus id, but it SUCCEEDED and returned {result!r}"
    )


def _create_api(ctx, ag):
    """Create a REGIONAL REST API (registered for teardown) and return its id."""
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    return api_id


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetRestApi on a bogus id must fail with NotFoundException (overly-permissive check)."""
    ag = ctx.client("apigateway")

    # Positive control: GetRestApi on a real id must succeed and return that id — otherwise a
    # NotFoundException on the bogus id is indistinguishable from GetRestApi being broken outright.
    real_api_id = _create_api(ctx, ag)
    got = ag.get_rest_api(restApiId=real_api_id)["id"]
    assert got == real_api_id, f"expected GetRestApi to return {real_api_id!r}, got {got!r}"

    code, message = _error(lambda: ag.get_rest_api(restApiId="nonexistent1"))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    expected = f"Invalid API identifier specified {ctx.account}:nonexistent1"
    assert message == expected, f"expected {expected!r}, got {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
