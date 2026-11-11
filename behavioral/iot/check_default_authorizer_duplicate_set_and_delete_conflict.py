"""default-authorizer-duplicate-set-and-delete-conflict."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "default-authorizer-duplicate-set-and-delete-conflict"
GROUP = 'overly-permissive'
SERVICES = ['iot']


def _err(fn):
    """Call fn(); return the ClientError (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _clear_default(iot):
    """Teardown: clear the account's default authorizer; only 'no default set' counts as clean."""
    try:
        iot.clear_default_authorizer()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:iot-default-authorizer")
def run(ctx) -> None:
    """SetDefaultAuthorizer rejects re-setting the same default, DeleteAuthorizer rejects deleting
    the current default, and ClearDefaultAuthorizer 404s once no default is left."""
    iot = ctx.client("iot")
    account = ctx.client("sts").get_caller_identity()["Account"]
    first = ctx.unique_name("sim2real-behav-defauthz-d1-")
    second = ctx.unique_name("sim2real-behav-defauthz-d2-")
    fn_arn = f"arn:aws:lambda:{ctx.region}:{account}:function:sim2real-behav-defauthz-fn"

    for name in (first, second):
        iot.create_authorizer(
            authorizerName=name,
            authorizerFunctionArn=fn_arn,
            signingDisabled=True,
            tags=[{"Key": "sim2real", "Value": CHECK}],
        )
        # Authorizers must be INACTIVE before deletion, so register both (LIFO: INACTIVE, delete).
        ctx.on_cleanup(lambda _n=name: iot.delete_authorizer(authorizerName=_n))
        ctx.on_cleanup(lambda _n=name: iot.update_authorizer(authorizerName=_n, status="INACTIVE"))
    ctx.on_cleanup(lambda: _clear_default(iot))

    # Positive control: setting a real default is observable through DescribeDefaultAuthorizer.
    iot.set_default_authorizer(authorizerName=first)
    got = iot.describe_default_authorizer()["authorizerDescription"]["authorizerName"]
    assert got == first, f"expected default {first!r} after set, got {got!r}"

    # Set the SAME name as default again.
    code, message = _err(lambda: iot.set_default_authorizer(authorizerName=first))
    expected = ("ResourceAlreadyExistsException",
                f"Duplicate default authorizer {first} already configured for this account")
    assert (code, message) == expected, (
        f"re-setting the same default authorizer must be rejected with {expected!r}, got "
        f"{(code, message)!r}"
    )
    # The rejected duplicate set must not have disturbed the default.
    got_after_dup = iot.describe_default_authorizer()["authorizerDescription"]["authorizerName"]
    assert got_after_dup == first, (
        f"rejected duplicate set must leave the default {first!r}, got {got_after_dup!r}"
    )

    # Setting a DIFFERENT name replaces the default (this is not a duplicate).
    iot.set_default_authorizer(authorizerName=second)
    got2 = iot.describe_default_authorizer()["authorizerDescription"]["authorizerName"]
    assert got2 == second, f"expected default replaced with {second!r}, got {got2!r}"

    # Delete the current default without changing it first.
    code2, message2 = _err(lambda: iot.delete_authorizer(authorizerName=second))
    expected2 = ("DeleteConflictException",
                 f"Cannot delete default authorizer {second}. Change default and retry delete.")
    assert (code2, message2) == expected2, (
        f"deleting the current default authorizer must be rejected with {expected2!r}, got "
        f"{(code2, message2)!r}"
    )
    # The rejected delete must not have taken effect: the authorizer is still describable.
    still_there = iot.describe_authorizer(authorizerName=second)["authorizerDescription"]["authorizerName"]
    assert still_there == second, f"rejected delete must leave {second!r} describable, got {still_there!r}"

    # Clear it, then clear again: the second clear has no default left to act on.
    iot.clear_default_authorizer()
    code3, message3 = _err(lambda: iot.describe_default_authorizer())
    assert (code3, message3) == ("ResourceNotFoundException", "Default authorizer not found"), (
        f"expected ResourceNotFoundException 'Default authorizer not found' after clearing the "
        f"default, got {(code3, message3)!r}"
    )
    code4, message4 = _err(lambda: iot.clear_default_authorizer())
    assert (code4, message4) == ("ResourceNotFoundException", "Default authorizer not found"), (
        f"re-clearing an already-cleared default must also 404 'Default authorizer not found', "
        f"got {(code4, message4)!r}"
    )

    # SetDefaultAuthorizer on a well-formed but nonexistent authorizer name is a distinct 404.
    missing = ctx.unique_name("sim2real-behav-defauthz-missing-")
    code5, message5 = _err(lambda: iot.set_default_authorizer(authorizerName=missing))
    assert (code5, message5) == ("ResourceNotFoundException", f"Authorizer {missing} not found"), (
        f"setting a nonexistent authorizer as default must 404 'Authorizer {missing} not found', "
        f"got {(code5, message5)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
