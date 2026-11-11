"""feature-unavailable-in-tier-domain-mfa-logging."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "feature-unavailable-in-tier-domain-mfa-logging"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _error(fn):
    """Call fn() and return its error (Code, Message); raise if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _retry_throttled(fn, *, max_attempts: int = 8, base_delay: float = 1.0):
    """Retry fn() with exponential backoff on TooManyRequestsException; other errors propagate."""
    delay = base_delay
    for attempt in range(max_attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "TooManyRequestsException" and attempt < max_attempts - 1:
                time.sleep(delay)
                delay = min(delay * 1.7, 15.0)
                continue
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A Lite pool gets FeatureUnavailableInTierException for managed login v2, email MFA and
    userAuthEvents log export, with no side effect; after raising the tier, the domain upgrade
    and log export succeed, so the refusal is tier-specific."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
        UserPoolTags=_TAGS,
        UserPoolTier="LITE",
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))
    domain = ctx.unique_name("sim2real-behav-cip-domain-").lower().replace("_", "-")

    # CreateUserPoolDomain: managed login (v2) isn't available on Lite.
    code1, message1 = _error(
        lambda: _retry_throttled(
            lambda: c.create_user_pool_domain(
                Domain=domain, UserPoolId=pool_id, ManagedLoginVersion=2
            )
        )
    )
    assert code1 == "FeatureUnavailableInTierException", (
        f"CreateUserPoolDomain: expected FeatureUnavailableInTierException, got {code1}"
    )
    assert message1 == "The following feature is not available for the LITE pricing tier configured: Managed Login Version 2", (
        f"expected the exact tier refusal message, got {message1!r}"
    )

    # Classic hosted UI (v1) IS available on Lite; create it, then try to
    # upgrade the SAME domain in place to managed login (v2).
    _retry_throttled(
        lambda: c.create_user_pool_domain(
            Domain=domain, UserPoolId=pool_id, ManagedLoginVersion=1
        )
    )
    ctx.on_cleanup(lambda: c.delete_user_pool_domain(Domain=domain, UserPoolId=pool_id))

    code2, message2 = _error(
        lambda: _retry_throttled(
            lambda: c.update_user_pool_domain(
                Domain=domain, UserPoolId=pool_id, ManagedLoginVersion=2
            )
        )
    )
    assert code2 == "FeatureUnavailableInTierException", (
        f"UpdateUserPoolDomain: expected FeatureUnavailableInTierException, got {code2}"
    )
    assert message2 == "The following feature is not available for the LITE pricing tier configured: Managed Login Version 2", (
        f"expected the exact tier refusal message, got {message2!r}"
    )
    domain_after_reject = c.describe_user_pool_domain(Domain=domain)["DomainDescription"]
    assert domain_after_reject.get("ManagedLoginVersion", 1) == 1, (
        "a rejected UpdateUserPoolDomain must not have upgraded the domain to managed login v2, "
        f"got ManagedLoginVersion={domain_after_reject.get('ManagedLoginVersion')!r}"
    )

    # SetUserPoolMfaConfig: email MFA is an Essentials/Plus-only feature.
    # Positive control FIRST: a plain MfaConfiguration="OFF" call (no
    # EmailMfaConfiguration) must succeed on this SAME Lite-tier pool, so the
    # EmailMfaConfiguration rejection below is specific to that feature, not
    # a blanket failure of SetUserPoolMfaConfig on a Lite pool.
    _retry_throttled(lambda: c.set_user_pool_mfa_config(UserPoolId=pool_id, MfaConfiguration="OFF"))

    email_mfa_config = {
        "Message": "Your verification code is {####}",
        "Subject": "Your verification code",
    }
    code3, message3 = _error(
        lambda: _retry_throttled(
            lambda: c.set_user_pool_mfa_config(
                UserPoolId=pool_id,
                EmailMfaConfiguration=email_mfa_config,
                MfaConfiguration="OPTIONAL",
            )
        )
    )
    assert code3 == "FeatureUnavailableInTierException", (
        f"SetUserPoolMfaConfig: expected FeatureUnavailableInTierException, got {code3}"
    )
    assert message3 == "The following feature is not available for the LITE pricing tier configured: Email MFA", (
        f"expected the exact tier refusal message, got {message3!r}"
    )
    mfa_after_reject = c.get_user_pool_mfa_config(UserPoolId=pool_id)
    assert not mfa_after_reject.get("EmailMfaConfiguration"), (
        "a rejected SetUserPoolMfaConfig must not have activated email MFA, got "
        f"{mfa_after_reject.get('EmailMfaConfiguration')!r}"
    )

    # SetLogDeliveryConfiguration: threat-protection user-activity log export
    # (userAuthEvents) requires the Plus tier.
    logs = ctx.client("logs")
    log_group_name = ctx.unique_name("sim2real-behav-cip-loggroup-")
    logs.create_log_group(logGroupName=log_group_name)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))
    # DescribeLogGroups returns the ARN with a trailing ":*" (all streams);
    # LogDeliveryConfiguration wants the bare log-group ARN, so strip it --
    # otherwise a malformed-ARN rejection would be indistinguishable, by code
    # alone, from the tier rejection this check exists to prove.
    log_group_arn = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"][0][
        "arn"
    ].removesuffix(":*")
    log_config = {
        "EventSource": "userAuthEvents",
        "LogLevel": "INFO",
        "CloudWatchLogsConfiguration": {"LogGroupArn": log_group_arn},
    }

    code4, message4 = _error(
        lambda: _retry_throttled(
            lambda: c.set_log_delivery_configuration(
                UserPoolId=pool_id, LogConfigurations=[log_config]
            )
        )
    )
    assert code4 == "FeatureUnavailableInTierException", (
        f"SetLogDeliveryConfiguration: expected FeatureUnavailableInTierException, got {code4!r}"
    )
    assert message4 == "The following feature is not available for the LITE pricing tier configured: Log Streaming", (
        f"expected the exact tier refusal message, got {message4!r}"
    )
    log_delivery_after_reject = c.get_log_delivery_configuration(UserPoolId=pool_id)[
        "LogDeliveryConfiguration"
    ]
    assert not log_delivery_after_reject.get("LogConfigurations"), (
        "a rejected SetLogDeliveryConfiguration must not have persisted the log export, got "
        f"{log_delivery_after_reject.get('LogConfigurations')!r}"
    )

    # RESTORE (1/2): raise the pool to Essentials -- managed login v2 and
    # email MFA are Essentials-and-above. The IDENTICAL calls just rejected
    # above must now succeed, proving the boundary is tier-specific rather
    # than a blanket refusal of these operations.
    _retry_throttled(lambda: c.update_user_pool(UserPoolId=pool_id, UserPoolTier="ESSENTIALS"))

    _retry_throttled(
        lambda: c.update_user_pool_domain(
            Domain=domain, UserPoolId=pool_id, ManagedLoginVersion=2
        )
    )
    domain_after_restore = c.describe_user_pool_domain(Domain=domain)["DomainDescription"]
    assert domain_after_restore.get("ManagedLoginVersion") == 2, (
        "UpdateUserPoolDomain to managed login v2 must succeed once the pool is Essentials-tier, "
        f"got ManagedLoginVersion={domain_after_restore.get('ManagedLoginVersion')!r}"
    )

    # Email MFA is not restored: on Essentials it also requires an SES-verified DEVELOPER
    # sending account, which cannot be created in-line.

    # RESTORE (2/2): raise the pool to Plus -- threat-protection log export is
    # Plus-only. The identical SetLogDeliveryConfiguration call must now
    # succeed and be visible through an independent read.
    _retry_throttled(lambda: c.update_user_pool(UserPoolId=pool_id, UserPoolTier="PLUS"))

    _retry_throttled(
        lambda: c.set_log_delivery_configuration(
            UserPoolId=pool_id, LogConfigurations=[log_config]
        )
    )
    log_delivery_after_restore = c.get_log_delivery_configuration(UserPoolId=pool_id)[
        "LogDeliveryConfiguration"
    ].get("LogConfigurations", [])
    assert any(
        lc.get("EventSource") == "userAuthEvents"
        and lc.get("CloudWatchLogsConfiguration", {}).get("LogGroupArn") == log_group_arn
        for lc in log_delivery_after_restore
    ), (
        "SetLogDeliveryConfiguration for userAuthEvents must succeed and be visible through "
        f"GetLogDeliveryConfiguration once the pool is Plus-tier, got {log_delivery_after_restore!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
