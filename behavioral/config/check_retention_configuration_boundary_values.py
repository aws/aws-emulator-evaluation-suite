"""retention-configuration-boundary-values."""

from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

def _retry_throttled(fn, attempts=8, base_delay=2.0):
    # Config's control plane has a very low burst limit; churning recorders/rules/
    # delivery-channels across checks reliably trips ThrottlingException. Retry those
    # transparently while re-raising any domain error a check asserts on.
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in ("ThrottlingException", "TooManyRequestsException"):
                raise
            last = exc
            time.sleep(base_delay * (2 ** min(attempt, 4)))
    raise last

def _clear_retention_configs(ctx):
    """Delete the account's retention configuration; cleanup restores its original period."""
    cfg = ctx.client("config")
    for rc in cfg.describe_retention_configurations().get("RetentionConfigurations", []):
        days = rc["RetentionPeriodInDays"]
        _retry_throttled(lambda n=rc["Name"]: cfg.delete_retention_configuration(RetentionConfigurationName=n))
        ctx.on_cleanup(lambda d=days: _retry_throttled(lambda: cfg.put_retention_configuration(RetentionPeriodInDays=d)))


def _delete_retention_quiet(cfg, name):
    try:
        _retry_throttled(lambda: cfg.delete_retention_configuration(RetentionConfigurationName=name))
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchRetentionConfigurationException":
            raise


def _retention_named(cfg, name):
    return [rc for rc in cfg.describe_retention_configurations()["RetentionConfigurations"] if rc["Name"] == name]

def _put_retention(ctx, days):
    cfg = ctx.client("config")
    return _retry_throttled(lambda: cfg.put_retention_configuration(RetentionPeriodInDays=days))

CHECK = "retention-configuration-boundary-values"
GROUP = 'retention-configuration'
SERVICES = ['config']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:config-retention")
def run(ctx) -> None:
    """RetentionPeriodInDays boundary values (30 minimum, 2557 maximum) must be
    stored exactly as supplied -- not clamped, rounded or defaulted."""
    cfg = ctx.client("config")
    _clear_retention_configs(ctx)

    for days in (30, 2557):
        put = _put_retention(ctx, days)["RetentionConfiguration"]
        assert put["RetentionPeriodInDays"] == days, put
        name = put["Name"]
        ctx.on_cleanup(lambda a=name: _delete_retention_quiet(cfg, a))
        described = _retention_named(cfg, name)
        assert [rc["RetentionPeriodInDays"] for rc in described] == [days], described

    # Out-of-range values are rejected by the client-side model before ever
    # reaching the service, so the server-side boundary is probed via the
    # accepted extremes above.
    cfg.delete_retention_configuration(RetentionConfigurationName=name)
    assert _retention_named(cfg, name) == []


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
