"""delete-cors-configuration-removes-config."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "delete-cors-configuration-removes-config"
GROUP = "state-machine"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteCorsConfiguration clears an API's CORS configuration so a
    subsequent GetApi no longer returns a CorsConfiguration block."""
    apigw = ctx.client("apigatewayv2")

    cors = {
        "AllowOrigins": ["https://sim2real.example.com"],
        "AllowMethods": ["GET", "POST"],
        "MaxAge": 100,
    }
    api = apigw.create_api(
        Name=ctx.unique_name("sim2real-behav-httpapi-"),
        ProtocolType="HTTP",
        CorsConfiguration=cors,
        Tags=TAGS,
    )
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: apigw.delete_api(ApiId=api_id))

    got = apigw.get_api(ApiId=api_id)
    assert got.get("CorsConfiguration", {}).get("AllowOrigins") == cors["AllowOrigins"], (
        f"positive control: GetApi should reflect the CorsConfiguration set at creation, "
        f"got {got.get('CorsConfiguration')!r}"
    )

    apigw.delete_cors_configuration(ApiId=api_id)

    got2 = _poll_until(
        lambda: apigw.get_api(ApiId=api_id),
        lambda a: not a.get("CorsConfiguration"),
        timeout_s=15,
    )
    assert not got2.get("CorsConfiguration"), (
        "GetApi still returns a CorsConfiguration block after "
        "DeleteCorsConfiguration"
    )


def _poll_until(probe, predicate, *, timeout_s=15.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
