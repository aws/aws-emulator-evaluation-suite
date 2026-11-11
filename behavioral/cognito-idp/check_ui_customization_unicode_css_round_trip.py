"""ui-customization-unicode-css-round-trip."""
from __future__ import annotations

import re
import time

from behavioral_harness import tags

CHECK = "ui-customization-unicode-css-round-trip"
GROUP = "representation"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetUICustomization CSS with unicode + long content round-trips byte-identical via GetUICustomization."""
    cognito = ctx.client("cognito-idp")

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-uicustom-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-uicustom"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    domain = _dns_safe(ctx.unique_name("sim2real-uic-"))
    cognito.create_user_pool_domain(Domain=domain, UserPoolId=pool_id)
    ctx.on_cleanup(lambda: _delete_domain_and_wait_gone(cognito, domain, pool_id))

    css_block = (
        "/* \u6d4b\u8bd5 \u00dcn\u00efc\u00f6d\u00e9 \u2603 \U0001F389 "
        "h\u00e9llo\u2013world \u00e9\u00e8\u00ea\u00eb \u0440\u0443\u0441\u0441\u043a\u0438\u0439 */\n"
        ".legalText-customizable {color: #1A2B3C;}\n"
    )
    css = css_block * 200  # push well past a trivial short string, well under the 131072 cap
    assert len(css) < 131072, f"test fixture bug: css length {len(css)} would hit the documented cap"

    _set_ui_customization_with_retry(ctx, cognito, pool_id, css)

    got = cognito.get_ui_customization(UserPoolId=pool_id, ClientId="ALL")["UICustomization"]
    got_css = got["CSS"]
    if got_css != css:
        first_diff = next((i for i, (a, b) in enumerate(zip(css, got_css)) if a != b), min(len(css), len(got_css)))
        raise AssertionError(
            "CSS content was not returned byte-identical: "
            f"sent_len={len(css)} got_len={len(got_css)} first_diff_at={first_diff} "
            f"sent_around={css[max(0, first_diff - 20):first_diff + 20]!r} "
            f"got_around={got_css[max(0, first_diff - 20):first_diff + 20]!r}"
        )


def _dns_safe(name: str) -> str:
    s = re.sub(r"[^a-z0-9-]", "-", name.lower())
    s = re.sub(r"-+", "-", s).strip("-")
    return s[:63] or "sim2real-uic"


def _delete_domain_and_wait_gone(
    cognito, domain: str, pool_id: str, timeout_s: float = 90.0, interval_s: float = 3.0
) -> None:
    """DeleteUserPoolDomain is asynchronous; deleting the pool before teardown finishes fails and
    that failure is swallowed by the harness's best-effort cleanup, leaking the pool. Poll gone.
    DescribeUserPoolDomain returns 200 with an empty DomainDescription for a gone domain rather
    than raising, so absence is a falsy/keyless body, not an exception."""
    cognito.delete_user_pool_domain(Domain=domain, UserPoolId=pool_id)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = cognito.describe_user_pool_domain(Domain=domain).get("DomainDescription")
        if not desc or not desc.get("UserPoolId"):
            return
        time.sleep(interval_s)
    raise AssertionError(f"user pool domain {domain} did not finish deleting within {timeout_s}s")


def _set_ui_customization_with_retry(ctx, cognito, pool_id: str, css: str, timeout_s: float = 90.0) -> None:
    """A fresh prefix domain can take up to ~1 minute to take effect (AWS docs), so poll."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            cognito.set_ui_customization(UserPoolId=pool_id, ClientId="ALL", CSS=css)
            return
        except cognito.exceptions.InvalidParameterException as exc:
            last_err = exc
            time.sleep(5)
    raise AssertionError(f"SetUICustomization never succeeded within {timeout_s}s: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
