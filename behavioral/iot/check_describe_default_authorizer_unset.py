"""describe-default-authorizer-unset."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-default-authorizer-unset"
GROUP = 'overly-permissive'
SERVICES = ['iot']

def _err(fn):
    """Return the (Error.Code, Error.Message) fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")

def _clear_default_authorizer_quiet(iot):
    """Teardown: clear the account default authorizer, tolerating one that is already unset."""
    try:
        iot.clear_default_authorizer()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:iot-default-authorizer")
def run(ctx) -> None:
    """DescribeDefaultAuthorizer returns ResourceNotFoundException once the default authorizer is
    cleared, and succeeds again once it is re-set, so the answer tracks account state."""
    iot = ctx.client("iot")
    account = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-behav-defauthz-")
    function_arn = f"arn:aws:lambda:{ctx.region}:{account}:function:sim2real-behav-defauthz-fn"

    iot.create_authorizer(
        authorizerName=name,
        authorizerFunctionArn=function_arn,
        status="ACTIVE",
        signingDisabled=True,
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iot.delete_authorizer(authorizerName=name))
    ctx.on_cleanup(lambda: iot.update_authorizer(authorizerName=name, status="INACTIVE"))
    ctx.on_cleanup(lambda: _clear_default_authorizer_quiet(iot))

    # Positive control: a set default authorizer is reported.
    iot.set_default_authorizer(authorizerName=name)
    desc = iot.describe_default_authorizer()
    got_name = desc["authorizerDescription"]["authorizerName"]
    assert got_name == name, f"expected default authorizer {name!r}, got {got_name!r}"

    iot.clear_default_authorizer()
    expected_message = "Default authorizer not found"
    code, message = _err(lambda: iot.describe_default_authorizer())
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException with no default authorizer, got {code}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    # A repeated read must not flip the state on its own (no advancing on reads).
    code_again, message_again = _err(lambda: iot.describe_default_authorizer())
    assert code_again == "ResourceNotFoundException", (
        f"repeated DescribeDefaultAuthorizer must stay ResourceNotFoundException, got {code_again}"
    )
    assert message_again == expected_message, (
        f"expected message {expected_message!r}, got {message_again!r}"
    )

    iot.set_default_authorizer(authorizerName=name)
    desc2 = iot.describe_default_authorizer()
    got_name2 = desc2["authorizerDescription"]["authorizerName"]
    assert got_name2 == name, f"expected restored default authorizer {name!r}, got {got_name2!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
