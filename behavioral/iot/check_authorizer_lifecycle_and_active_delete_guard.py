"""authorizer-lifecycle-and-active-delete-guard."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "authorizer-lifecycle-and-active-delete-guard"
GROUP = 'overly-permissive'
SERVICES = ['iot']

def _err(fn):
    """Call fn(); return the botocore (code, message) of the ClientError raised. An unexpected
    SUCCESS raises, because an emulator ACCEPTING a call real AWS refuses is the strongest signal
    available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

def _gone_ok(fn):
    """Teardown step that tolerates the resource already being deleted."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An ACTIVE custom authorizer cannot be deleted; it must be set INACTIVE first."""
    iot = ctx.client("iot")
    account = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-behav-authz-")
    function_arn = f"arn:aws:lambda:{ctx.region}:{account}:function:sim2real-behav-authz-fn"
    iot.create_authorizer(
        authorizerName=name,
        authorizerFunctionArn=function_arn,
        status="ACTIVE",
        signingDisabled=True,
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    # Authorizers must be INACTIVE before deletion, so register both (LIFO: INACTIVE, then delete);
    # the check deletes the authorizer itself, so teardown tolerates it being gone.
    ctx.on_cleanup(lambda _n=name: _gone_ok(lambda: iot.delete_authorizer(authorizerName=_n)))
    ctx.on_cleanup(lambda _n=name: _gone_ok(
        lambda: iot.update_authorizer(authorizerName=_n, status="INACTIVE")))

    desc = iot.describe_authorizer(authorizerName=name)
    status = desc["authorizerDescription"]["status"]
    assert status == "ACTIVE", f"expected ACTIVE after create, got {status}"

    code = _err(lambda: iot.delete_authorizer(authorizerName=name))
    assert code == ("InvalidRequestException", f"Cannot delete authorizer {name} in ACTIVE status. Update status to INACTIVE and delete."), (
        f"deleting an ACTIVE authorizer must be rejected, got {code}"
    )

    # The rejected delete must not have taken effect: an independent read still sees it, ACTIVE.
    desc_after_reject = iot.describe_authorizer(authorizerName=name)
    status_after_reject = desc_after_reject["authorizerDescription"]["status"]
    assert status_after_reject == "ACTIVE", (
        f"rejected delete must leave the authorizer ACTIVE, got {status_after_reject}"
    )

    iot.update_authorizer(authorizerName=name, status="INACTIVE")
    desc2 = iot.describe_authorizer(authorizerName=name)
    status2 = desc2["authorizerDescription"]["status"]
    assert status2 == "INACTIVE", f"expected INACTIVE after update, got {status2}"

    names = [a["authorizerName"] for a in iot.list_authorizers().get("authorizers", [])]
    assert name in names, f"{name} missing from ListAuthorizers"

    iot.delete_authorizer(authorizerName=name)
    code2 = _err(lambda: iot.describe_authorizer(authorizerName=name))
    assert code2 == ("ResourceNotFoundException", f"Authorizer {name} not found"), (
        f"expected ResourceNotFoundException for the deleted authorizer, got {code2!r}"
    )

    # The dead id is not just unreadable, it is unusable: a mutation on it fails identically.
    code3 = _err(lambda: iot.update_authorizer(authorizerName=name, status="INACTIVE"))
    assert code3 == ("ResourceNotFoundException", f"Authorizer {name} not found"), (
        f"mutating the deleted authorizer must also 404, got {code3}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
