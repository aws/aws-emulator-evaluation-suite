"""reject-api-domain-association-mismatched-state."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")

def _create_event_api(ctx, svc):
    api = svc.create_api(
        name=ctx.unique_name("sim2real-behav-appsync-eventapi-"),
        eventConfig={"authProviders": [{"authType": "API_KEY"}, {"authType": "AWS_IAM"}], "connectionAuthModes": [{"authType": "API_KEY"}], "defaultPublishAuthModes": [{"authType": "API_KEY"}], "defaultSubscribeAuthModes": [{"authType": "API_KEY"}]},
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["api"]
    ctx.on_cleanup(lambda _a=api: svc.delete_api(apiId=_a["apiId"]))
    return api

CHECK = "reject-api-domain-association-mismatched-state"
GROUP = 'overly-permissive'
SERVICES = ['appsync']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateApi, GetApiAssociation and DisassociateApi on a never-created domain all fail with
    NotFoundException; a rejected AssociateApi leaves no partial state for a second Api to use."""
    svc = ctx.client("appsync")
    domain = f"{ctx.unique_name('sim2real-behav-dn-')}.com"
    api_a = _create_event_api(ctx, svc)
    api_a_id = api_a["apiId"]
    api_b = _create_event_api(ctx, svc)
    api_b_id = api_b["apiId"]

    code1, message1 = _error(lambda: svc.associate_api(domainName=domain, apiId=api_a_id))
    assert code1 == "NotFoundException", (
        f"expected NotFoundException associating a nonexistent domain, got {code1}"
    )
    assert message1 == "Domain name not found.", f"unexpected NotFoundException message {message1!r}"

    # A different Api must fail identically: the first rejected call left no partial association.
    code2, message2 = _error(lambda: svc.associate_api(domainName=domain, apiId=api_b_id))
    assert code2 == "NotFoundException", (
        f"expected the second AssociateApi attempt (different Api, same nonexistent domain) to fail "
        f"identically, got {code2}"
    )
    assert message2 == "Domain name not found.", f"unexpected NotFoundException message {message2!r}"

    code3, message3 = _error(lambda: svc.get_api_association(domainName=domain))
    assert code3 == "NotFoundException", (
        f"expected NotFoundException from GetApiAssociation on a domain with no association, got {code3}"
    )
    assert message3 == "Domain name not found", f"unexpected NotFoundException message {message3!r}"

    code4, message4 = _error(lambda: svc.disassociate_api(domainName=domain))
    assert code4 == "NotFoundException", (
        f"expected NotFoundException disassociating a domain with no association, got {code4}"
    )
    assert message4 == "Domain name not found.", f"unexpected NotFoundException message {message4!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
