"""http-api-list-reflects-created."""
from __future__ import annotations

from behavioral_harness import tags

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}

CHECK = "http-api-list-reflects-created"
GROUP = 'http-api'
SERVICES = ['apigatewayv2']

def _in_apis_list(agw, api_id) -> bool:
    token = None
    for _ in range(50):
        kwargs = {"MaxResults": "100"}
        if token:
            kwargs["NextToken"] = token
        resp = agw.get_apis(**kwargs)
        if any(item["ApiId"] == api_id for item in resp.get("Items", [])):
            return True
        token = resp.get("NextToken")
        if not token:
            break
    return False


@tags("axis:happy-path", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A freshly-created HTTP API appears in GetApis, and a deleted one disappears
    from it (assert on OUR own id, both ways)."""
    agw = ctx.client("apigatewayv2")
    created = agw.create_api(Name=ctx.unique_name("sim2real-behav-httpapi-"), ProtocolType="HTTP", Tags=TAGS)
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=created["ApiId"]))
    api_id = created["ApiId"]

    assert _in_apis_list(agw, api_id), f"created api {api_id} not found in GetApis"

    agw.delete_api(ApiId=api_id)
    assert not _in_apis_list(agw, api_id), f"deleted api {api_id} still present in GetApis"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
