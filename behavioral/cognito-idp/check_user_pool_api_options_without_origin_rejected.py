"""user-pool-api-options-without-origin-rejected."""
from __future__ import annotations

import requests

from behavioral_harness import tags

CHECK = "user-pool-api-options-without-origin-rejected"
GROUP = "browser-cors"
SERVICES = ["cognito-idp"]

ORIGIN = "https://app.example.com"


def _options(ctx, headers: dict):
    url = ctx.service_url(f"https://cognito-idp.{ctx.region}.amazonaws.com")
    return requests.request("OPTIONS", url + "/", headers=headers, timeout=30, verify=ctx.http_verify)


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An OPTIONS request with no Origin is not a CORS preflight: the user pool API refuses it as an
    unknown operation with no CORS headers, while the same request carrying Origin is answered.
    """
    # Positive control: the identical request plus Origin is a preflight and is allowed.
    ok = _options(ctx, {"Origin": ORIGIN, "Access-Control-Request-Method": "POST"})
    assert ok.status_code == 200, f"preflight with Origin answered {ok.status_code}: {ok.text[:300]!r}"
    assert ok.headers.get("Access-Control-Allow-Origin") == "*", (
        f"Access-Control-Allow-Origin was {ok.headers.get('Access-Control-Allow-Origin')!r}"
    )

    r = _options(ctx, {"Access-Control-Request-Method": "POST"})
    assert r.status_code == 400, f"OPTIONS without Origin answered {r.status_code}: {r.text[:300]!r}"
    body = r.json()
    assert body == {
        "code": "BadRequest",
        "message": "The server did not understand the operation that was requested.",
        "type": "client",
    }, f"OPTIONS without Origin answered body {body!r}"
    leaked = sorted(k for k in r.headers if k.lower().startswith("access-control-"))
    assert leaked == [], f"a non-CORS OPTIONS carried CORS headers: {leaked!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
