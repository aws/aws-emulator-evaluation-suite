"""get-stages-pagination-chains-every-stage-once."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-stages-pagination-chains-every-stage-once"
GROUP = "stages"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_STAGES = ["alpha", "beta", "gamma", "delta", "epsilon"]


def _error(fn):
    """(code, message) of the ClientError fn() raised. An unexpected success RAISES."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetStages with MaxResults=2 over an API with five stages returns pages of at most two, and
    following NextToken visits every stage exactly once, then stops; an unissued token is refused.
    """
    agw = ctx.client("apigatewayv2")
    api_id = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-httpapi-"), ProtocolType="HTTP", Tags=TAGS
    )["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=api_id))
    for name in _STAGES:
        agw.create_stage(ApiId=api_id, StageName=name)

    seen, sizes, token = [], [], None
    for _ in range(20):
        kw = {"ApiId": api_id, "MaxResults": "2"}
        if token:
            kw["NextToken"] = token
        page = agw.get_stages(**kw)
        items = page.get("Items", [])
        sizes.append(len(items))
        seen.extend(s["StageName"] for s in items)
        token = page.get("NextToken")
        if not token:
            break
    else:
        raise AssertionError(f"GetStages pagination did not end within 20 pages; sizes {sizes}")
    assert all(n <= 2 for n in sizes), f"GetStages MaxResults=2 returned page sizes {sizes!r}"
    assert len(seen) == len(set(seen)), f"a stage appeared on two pages: {seen!r}"
    assert sorted(seen) == sorted(_STAGES), f"the chain must visit the five stages once, got {seen!r}"

    code, message = _error(
        lambda: agw.get_stages(ApiId=api_id, MaxResults="2", NextToken="sim2real-not-a-token")
    )
    assert code == "BadRequestException", (
        f"an unissued NextToken: expected BadRequestException, got {code}: {message!r}"
    )
    assert message == "Invalid position parameter", f"unexpected message {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

