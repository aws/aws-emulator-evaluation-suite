"""user-pool-api-cors-preflight-echoes-requested-method-and-headers."""
from __future__ import annotations

import requests

from behavioral_harness import tags

CHECK = "user-pool-api-cors-preflight-echoes-requested-method-and-headers"
GROUP = "browser-cors"
SERVICES = ["cognito-idp"]

ORIGIN = "https://app.example.com"
EXPOSE = "x-amzn-RequestId,x-amzn-ErrorType,x-amzn-ErrorMessage,Date"


def _preflight(ctx, method: str, headers: str | None):
    url = ctx.service_url(f"https://cognito-idp.{ctx.region}.amazonaws.com")
    sent = {"Origin": ORIGIN, "Access-Control-Request-Method": method}
    if headers is not None:
        sent["Access-Control-Request-Headers"] = headers
    return requests.request("OPTIONS", url + "/", headers=sent, timeout=30, verify=ctx.http_verify)


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A browser CORS preflight to the user pool API is answered 200 for any origin, echoing the
    requested method and headers and exposing the error-type headers a browser SDK reads.

    Reference: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pools-API-operations.html
    """
    sdk_headers = "content-type,x-amz-target,x-amz-user-agent"
    r = _preflight(ctx, "POST", sdk_headers)
    assert r.status_code == 200, f"preflight answered {r.status_code}: {r.text[:300]!r}"
    h = r.headers
    assert h.get("Access-Control-Allow-Origin") == "*", (
        f"Access-Control-Allow-Origin was {h.get('Access-Control-Allow-Origin')!r}"
    )
    assert h.get("Access-Control-Allow-Methods") == "POST", (
        f"Access-Control-Allow-Methods was {h.get('Access-Control-Allow-Methods')!r}"
    )
    assert h.get("Access-Control-Allow-Headers") == sdk_headers, (
        f"Access-Control-Allow-Headers was {h.get('Access-Control-Allow-Headers')!r}"
    )
    assert h.get("Access-Control-Expose-Headers") == EXPOSE, (
        f"Access-Control-Expose-Headers was {h.get('Access-Control-Expose-Headers')!r}"
    )
    assert h.get("Access-Control-Max-Age") == "172800", (
        f"Access-Control-Max-Age was {h.get('Access-Control-Max-Age')!r}"
    )
    assert r.content == b"", f"preflight carried a body: {r.text[:300]!r}"

    # The allow-lists are echoes of the request, not a fixed list: a header the SDK never sends is
    # allowed back as asked, and a preflight naming no headers gets no Allow-Headers at all.
    other = _preflight(ctx, "POST", "x-example-trace")
    assert other.status_code == 200, f"second preflight answered {other.status_code}"
    assert other.headers.get("Access-Control-Allow-Headers") == "x-example-trace", (
        f"Access-Control-Allow-Headers was {other.headers.get('Access-Control-Allow-Headers')!r}"
    )
    bare = _preflight(ctx, "PUT", None)
    assert bare.status_code == 200, f"header-less preflight answered {bare.status_code}"
    assert bare.headers.get("Access-Control-Allow-Methods") == "PUT", (
        f"Access-Control-Allow-Methods was {bare.headers.get('Access-Control-Allow-Methods')!r}"
    )
    assert "Access-Control-Allow-Headers" not in bare.headers, (
        f"Access-Control-Allow-Headers present without a request for it: "
        f"{bare.headers.get('Access-Control-Allow-Headers')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
