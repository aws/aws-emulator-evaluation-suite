"""disassociate-api-without-association-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "disassociate-api-without-association-rejected"
GROUP = "overly-permissive"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DisassociateApi against a domain name that has no existing API
    association must fail with NotFoundException, never silently succeed
    (even though a real, live Api exists in the account)."""
    appsync = ctx.client("appsync")

    api_id = _create_event_api(ctx)

    # A syntactically valid custom domain that was never registered/associated
    # with anything -- in particular, never linked to the Api we just created.
    never_associated_domain = f"{ctx.unique_name('sim2real-behav-noassoc-')}.example.com".lower()

    err = _error(lambda: appsync.disassociate_api(domainName=never_associated_domain))
    assert err == ("NotFoundException", "Domain name not found."), (
        f"expected NotFoundException disassociating a never-associated domain, got {err!r}"
    )

    # Confirm the Api itself is unaffected and still describable (the rejected
    # call must not have had any side effect on it).
    got = appsync.get_api(apiId=api_id)["api"]
    assert got["apiId"] == api_id, (
        f"expected the rejected DisassociateApi to leave the Api unaffected, "
        f"GetApi returned apiId={got.get('apiId')!r} for created api_id={api_id!r}"
    )


def _create_event_api(ctx) -> str:
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-behav-eapi-")
    event_config = {
        "authProviders": [{"authType": "API_KEY"}],
        "connectionAuthModes": [{"authType": "API_KEY"}],
        "defaultPublishAuthModes": [{"authType": "API_KEY"}],
        "defaultSubscribeAuthModes": [{"authType": "API_KEY"}],
    }
    api_id = appsync.create_api(name=name, eventConfig=event_config)["api"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_api(apiId=api_id))
    return api_id


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    over-permissive target accepting a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
