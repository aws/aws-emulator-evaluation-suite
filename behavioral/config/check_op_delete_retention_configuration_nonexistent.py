"""op-delete-retention-configuration-nonexistent."""

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


def _retention_named(cfg, name):
    return [rc for rc in cfg.describe_retention_configurations()["RetentionConfigurations"] if rc["Name"] == name]

def _put_retention(ctx, days):
    cfg = ctx.client("config")
    return _retry_throttled(lambda: cfg.put_retention_configuration(RetentionPeriodInDays=days))

CHECK = "op-delete-retention-configuration-nonexistent"
GROUP = 'overly-permissive'
SERVICES = ['config']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:config-retention")
def run(ctx) -> None:
    """DeleteRetentionConfiguration must raise
    NoSuchRetentionConfigurationException when no retention configuration
    exists at all -- a lenient emulator would return success."""
    cfg = ctx.client("config")
    _clear_retention_configs(ctx)

    # Positive control: prove the delete path genuinely removes a real
    # retention configuration before trusting its refusal below -- otherwise a
    # target that unconditionally raises NoSuchRetentionConfigurationException
    # on every DeleteRetentionConfiguration call, real or not, would score the
    # same as one that actually tracks state.
    name = _put_retention(ctx, 30)["RetentionConfiguration"]["Name"]
    ctx.on_cleanup(lambda: _delete_retention_quiet(cfg, name))
    described = _retention_named(cfg, name)
    assert [rc["RetentionPeriodInDays"] for rc in described] == [30], described
    cfg.delete_retention_configuration(RetentionConfigurationName=name)
    assert _retention_named(cfg, name) == []

    code, message = _error(
        lambda: cfg.delete_retention_configuration(
            RetentionConfigurationName=name
        )
    )
    assert code == "NoSuchRetentionConfigurationException", code
    assert message == f"Cannot find retention configuration with specified name '{name}'.", message

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
