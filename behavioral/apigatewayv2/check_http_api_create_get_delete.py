"""http-api-create-get-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}

CHECK = "http-api-create-get-delete"
GROUP = 'http-api'
SERVICES = ['apigatewayv2']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateApi(HTTP) -> GetApi reflects fields -> DeleteApi -> unreadable, unlisted, unmutable."""
    agw = ctx.client("apigatewayv2")
    name = ctx.unique_name("sim2real-behav-httpapi-lifecycle-")
    created = agw.create_api(Name=name, ProtocolType="HTTP", Tags=TAGS)
    api_id = created["ApiId"]
    ctx.on_cleanup(lambda: _delete_api_if_present(agw, api_id))
    assert created["ProtocolType"] == "HTTP", f"expected HTTP, got {created.get('ProtocolType')}"

    got = agw.get_api(ApiId=api_id)
    assert got["Name"] == name, f"expected name {name}, got {got.get('Name')}"
    assert got["ProtocolType"] == "HTTP", f"expected HTTP, got {got.get('ProtocolType')}"

    assert api_id in {a["ApiId"] for a in _all_apis(agw)}, f"API {api_id} not listed by GetApis before the delete"
    agw.delete_api(ApiId=api_id)
    # Beat 1: the by-id read is NotFoundException 404 with the exact message.
    code, message, status = _error(lambda: agw.get_api(ApiId=api_id))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}: {message!r}"
    assert isinstance(status, int) and 400 <= status < 500, f"expected an HTTP 4xx for GetApi after delete, got {status!r}"
    expected_message = f"Invalid API identifier specified {ctx.account}:{api_id}"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    # Beat 2: the deleted API is absent from the full (paginated) GetApis listing.
    survivors = [a for a in _all_apis(agw) if a.get("ApiId") == api_id or a.get("Name") == name]
    assert survivors == [], f"deleted API still listed by GetApis: {survivors!r}"

    # Beat 3: a mutation on the dead id is refused.
    code, message, status = _error(lambda: agw.update_api(ApiId=api_id, Description="post-delete"))
    assert code == "NotFoundException", f"expected NotFoundException updating the deleted API, got {code}"
    assert isinstance(status, int) and 400 <= status < 500, f"expected an HTTP 4xx for UpdateApi after delete, got {status!r}"
    expected_message = f"Invalid API identifier specified {ctx.account}:{api_id}"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"


def _all_apis(agw):
    """Every API GetApis returns, following NextToken."""
    items, token = [], None
    while True:
        page = agw.get_apis(**({"NextToken": token} if token else {}))
        items += page.get("Items", [])
        token = page.get("NextToken")
        if not token:
            return items


def _error(fn):
    """Call fn; return the ClientError (code, message, HTTP status). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message"), exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _delete_api_if_present(agw, api_id):
    try:
        agw.delete_api(ApiId=api_id)
    except agw.exceptions.NotFoundException:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
