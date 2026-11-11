"""set-ui-customization-oversized-css-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-ui-customization-oversized-css-rejected"
GROUP = "overly-permissive"
SERVICES = ["cognito-idp"]

_CSS_MAX_LEN = 131072  # documented Length Constraints maximum for the CSS field


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetUICustomization with CSS over 131072 characters fails with InvalidParameterException and its
    exact message and stores no CSS, while CSS of exactly 131072 characters is stored."""
    cognito = ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    # SetUICustomization (and GetUICustomization) require the pool to have an associated
    # classic-hosted-UI domain; without one every call fails with InvalidParameterException
    # regardless of the CSS payload, so provision a domain before exercising the size boundary.
    domain = ctx.unique_name("sim2real-behav-domain").lower().replace("_", "-")
    cognito.create_user_pool_domain(Domain=domain, UserPoolId=pool_id)
    ctx.on_cleanup(lambda: cognito.delete_user_pool_domain(Domain=domain, UserPoolId=pool_id))

    oversized_css = _build_valid_css(_CSS_MAX_LEN + 1)
    code, message = _error(
        lambda: cognito.set_ui_customization(UserPoolId=pool_id, ClientId="ALL", CSS=oversized_css)
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    expected_message = (
        f"1 validation error detected: Value '{oversized_css}' at 'cSS' failed to satisfy "
        f"constraint: Member must have length less than or equal to {_CSS_MAX_LEN}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: no CSS was persisted by the rejected, oversized attempt
    before = cognito.get_ui_customization(UserPoolId=pool_id, ClientId="ALL")["UICustomization"]
    assert before.get("CSS") is None, f"expected no CSS persisted after the rejected oversized SetUICustomization, got {before.get('CSS')!r}"

    # positive control: a payload at exactly the documented maximum is accepted
    max_css = _build_valid_css(_CSS_MAX_LEN)
    cognito.set_ui_customization(UserPoolId=pool_id, ClientId="ALL", CSS=max_css)
    after = cognito.get_ui_customization(UserPoolId=pool_id, ClientId="ALL")["UICustomization"]
    assert after["CSS"] == max_css, f"expected the max-length ({_CSS_MAX_LEN}) CSS payload to be persisted, got length {len(after.get('CSS') or '')}"


def _build_valid_css(total_len: int) -> str:
    """Build a syntactically-valid CSS document of exactly total_len characters, using a
    trailing comment as padding so the size boundary is isolated from content validity."""
    prefix = ".background-customizable{color:#000}/*"
    suffix = "*/"
    pad_len = total_len - len(prefix) - len(suffix)
    assert pad_len >= 0, f"total_len {total_len} too small for the fixed CSS scaffold"
    return prefix + ("a" * pad_len) + suffix


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

