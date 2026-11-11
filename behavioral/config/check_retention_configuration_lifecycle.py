"""retention-configuration-lifecycle."""

from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")

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

def _put_retention(ctx, days):
    cfg = ctx.client("config")
    return _retry_throttled(lambda: cfg.put_retention_configuration(RetentionPeriodInDays=days))

CHECK = "retention-configuration-lifecycle"
GROUP = 'retention-configuration'
SERVICES = ['config']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:config-retention")
def run(ctx) -> None:
    """PutRetentionConfiguration manages a single singleton (name "default"):
    repeated Put calls update the same object in place, DeleteRetentionConfiguration
    requires the exact current name, and after delete the singleton is gone."""
    cfg = ctx.client("config")
    _clear_retention_configs(ctx)

    _put_retention(ctx, 90)
    described = cfg.describe_retention_configurations()["RetentionConfigurations"]
    assert len(described) == 1, described
    # The wire member is "Name" (DeleteRetentionConfiguration takes it as
    # RetentionConfigurationName) -- AWS Config always names this singleton
    # "default".
    name = described[0]["Name"]
    assert name == "default", described[0]
    assert described[0]["RetentionPeriodInDays"] == 90, described[0]
    ctx.on_cleanup(lambda a=name: _delete_retention_quiet(cfg, a))

    _put_retention(ctx, 400)
    described = cfg.describe_retention_configurations()["RetentionConfigurations"]
    assert len(described) == 1, described
    assert described[0]["Name"] == name, described[0]
    assert described[0]["RetentionPeriodInDays"] == 400, described[0]

    # Deleting under the wrong name must fail even though a retention
    # configuration does exist -- exact-name matching, not "any exists".
    code, message = _error(
        lambda: cfg.delete_retention_configuration(
            RetentionConfigurationName=name + "-wrong"
        )
    )
    assert code == "NoSuchRetentionConfigurationException", code
    assert message == f"Cannot find retention configuration with specified name '{name}-wrong'.", message

    cfg.delete_retention_configuration(RetentionConfigurationName=name)
    described = cfg.describe_retention_configurations()["RetentionConfigurations"]
    assert described == [], described


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
