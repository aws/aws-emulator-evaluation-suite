"""configuration-recorder-max-number-exceeded."""

from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

_CONFIG_ROLE_NAME = "sim2real-behav-config-role"
_CONFIG_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "config.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)
_CONFIG_MANAGED_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
_ROLE_ARN_CACHE = None

_DEFAULT_RECORDING_GROUP = {"allSupported": True, "includeGlobalResourceTypes": False}

def _error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _absent_ok(fn, gone_code):
    """Cleanup step: run fn(); only the not-found code for a resource the check already
    deleted is tolerated, every other error propagates."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != gone_code:
            raise


def _retry_throttled(fn, attempts=8, base_delay=2.0):
    # Config's control plane has a very low burst limit; churning recorders/rules/
    # delivery-channels across checks reliably trips ThrottlingException. A freshly
    # created IAM role is also not immediately assumable by Config, which surfaces as
    # InvalidRoleException until the role has propagated. Retry both transparently
    # while re-raising any other domain error a check asserts on.
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in ("ThrottlingException", "TooManyRequestsException", "InvalidRoleException"):
                raise
            last = exc
            time.sleep(base_delay * (2 ** min(attempt, 4)))
    raise last

def _trusts_config_service(doc):
    """True only if the trust policy names the EXACT config.amazonaws.com principal
    (a substring test would also match the third-party service-linked role which
    Config cannot assume for standard recording/delivery)."""
    import urllib.parse as _up

    if isinstance(doc, str):
        try:
            doc = json.loads(_up.unquote(doc))
        except Exception:
            return False
    if not isinstance(doc, dict):
        return False
    for stmt in doc.get("Statement", []):
        principal = stmt.get("Principal", {})
        svc = principal.get("Service") if isinstance(principal, dict) else None
        svcs = svc if isinstance(svc, list) else [svc]
        if "config.amazonaws.com" in svcs:
            return True
    return False

def _ensure_config_role(ctx):
    """Resolve a role ARN usable as ConfigurationRecorder.roleARN: reuse an
    existing recorder's role, then an existing Config-trusted role, then create
    one. Skip if none is available and the caller lacks iam:CreateRole."""
    global _ROLE_ARN_CACHE
    if _ROLE_ARN_CACHE:
        return _ROLE_ARN_CACHE
    cfg = ctx.client("config")
    iam = ctx.client("iam")
    arn = None
    # 1. reuse the role of a recorder that already exists in the account.
    try:
        for r in cfg.describe_configuration_recorders().get("ConfigurationRecorders", []):
            if r.get("roleARN"):
                arn = r["roleARN"]
                break
    except Exception:
        pass
    # 2. an already-provisioned role Config can assume.
    if not arn:
        for nm in ("config-role", "AWSConfigRole", "AWSServiceRoleForConfig"):
            try:
                role = iam.get_role(RoleName=nm)["Role"]
                if _trusts_config_service(role.get("AssumeRolePolicyDocument")):
                    arn = role["Arn"]
                    break
            except Exception:
                continue
    if not arn:
        try:
            for page in iam.get_paginator("list_roles").paginate():
                for role in page.get("Roles", []):
                    if _trusts_config_service(role.get("AssumeRolePolicyDocument")):
                        arn = role["Arn"]
                        break
                if arn:
                    break
        except Exception:
            pass
    # 3. create one.
    if not arn:
        try:
            arn = iam.create_role(
                RoleName=_CONFIG_ROLE_NAME,
                AssumeRolePolicyDocument=_CONFIG_TRUST_POLICY,
                Description="sim2real behavioral fidelity probe role for AWS Config",
            )["Role"]["Arn"]
            try:
                iam.attach_role_policy(
                    RoleName=_CONFIG_ROLE_NAME, PolicyArn=_CONFIG_MANAGED_POLICY_ARN
                )
            except Exception:
                pass
            # IAM is eventually consistent; Config's pass-role validation fails with
            # InvalidRoleException until the new role has propagated. _retry_throttled
            # bounds that wait on the caller's next put_configuration_recorder instead
            # of a blind sleep here.
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "EntityAlreadyExists":
                arn = iam.get_role(RoleName=_CONFIG_ROLE_NAME)["Role"]["Arn"]
            else:
                arn = None
    if not arn:
        raise AssertionError(
            "no AWS Config service role is available in this account and the caller "
            "lacks iam:CreateRole, so no configuration recorder can be created"
        )
    _ROLE_ARN_CACHE = arn
    return arn

def _clear_recorders(ctx):
    cfg = ctx.client("config")
    try:
        recs = cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
    except Exception:
        return
    for rec in recs:
        name = rec.get("name")
        try:
            _retry_throttled(lambda n=name: cfg.stop_configuration_recorder(ConfigurationRecorderName=n))
        except Exception:
            pass
        try:
            _retry_throttled(lambda n=name: cfg.delete_configuration_recorder(ConfigurationRecorderName=n))
        except Exception:
            pass

def _create_recorder(ctx, name, recording_group=None, role_arn=None):
    cfg = ctx.client("config")
    recorder = {
        "name": name,
        "roleARN": role_arn or _ensure_config_role(ctx),
        "recordingGroup": recording_group or dict(_DEFAULT_RECORDING_GROUP),
    }
    _retry_throttled(lambda: cfg.put_configuration_recorder(ConfigurationRecorder=recorder))
    ctx.on_cleanup(
        lambda: _absent_ok(
            lambda: _retry_throttled(
                lambda: cfg.delete_configuration_recorder(ConfigurationRecorderName=name)
            ),
            "NoSuchConfigurationRecorderException",
        )
    )
    return name

CHECK = "configuration-recorder-max-number-exceeded"
GROUP = 'configuration-recorder'
SERVICES = ['config']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """AWS Config allows only one customer-managed configuration recorder per
    account/region; creating a second must fail while the first occupies the slot,
    and freeing that slot lets the identical create succeed (positive control)."""
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    _clear_recorders(ctx)
    first = ctx.unique_name("sim2real-behav-cfg-recorder-")
    _create_recorder(ctx, first)
    role_arn = _ensure_config_role(ctx)

    second = ctx.unique_name("sim2real-behav-cfg-recorder-")
    second_recorder = {
        "name": second,
        "roleARN": role_arn,
        "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": False},
    }
    # retry_throttled retries Config's low-burst-limit ThrottlingException but
    # re-raises the MaxNumberOfConfigurationRecordersExceededException we expect,
    # so error_code still captures it. Without the guard a transient throttle
    # masks the real singleton-limit error and fails the check intermittently.
    code, code_message = _error(
        lambda: _retry_throttled(lambda: cfg.put_configuration_recorder(ConfigurationRecorder=second_recorder))
    )
    assert code == "MaxNumberOfConfigurationRecordersExceededException", (
        f"expected MaxNumberOfConfigurationRecordersExceededException while the slot "
        f"is occupied, got {code!r}"
    )
    assert code_message == (
        "Failed to put configuration recorder  because you have reached the limit for the "
        "maximum number of customer managed configuration records: (1)"
    ), code_message

    recorders = cfg.describe_configuration_recorders()["ConfigurationRecorders"]
    assert all(r["name"] != second for r in recorders), (
        f"the rejected recorder {second!r} must not appear, got {recorders!r}"
    )

    # Positive control: freeing the occupied slot lets the identical create succeed.
    _retry_throttled(lambda: cfg.delete_configuration_recorder(ConfigurationRecorderName=first))
    _retry_throttled(lambda: cfg.put_configuration_recorder(ConfigurationRecorder=second_recorder))
    ctx.on_cleanup(
        lambda: _absent_ok(
            lambda: _retry_throttled(
                lambda: cfg.delete_configuration_recorder(ConfigurationRecorderName=second)
            ),
            "NoSuchConfigurationRecorderException",
        )
    )
    restored = cfg.describe_configuration_recorders()["ConfigurationRecorders"]
    assert any(r["name"] == second for r in restored), (
        f"expected {second!r} present once the slot was freed, got {restored!r}"
    )


def _restore_config_recorder_on_teardown(ctx) -> None:
    """The Config recorder and delivery channel exist once per account and Region: read them now
    and, in a teardown that runs after the check's own, put back exactly what was there."""
    import time

    from botocore.exceptions import ClientError

    cfg = ctx.client("config")

    def _call(fn):
        deadline = time.monotonic() + 60.0
        while True:
            try:
                return fn()
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ThrottlingException" or time.monotonic() > deadline:
                    raise
                time.sleep(2.0)

    def _recorders():
        found = _call(cfg.describe_configuration_recorders)["ConfigurationRecorders"]
        return [r for r in found if not r.get("servicePrincipal")]

    recorders = _recorders()
    statuses = _call(cfg.describe_configuration_recorder_status)["ConfigurationRecordersStatus"]
    recording = {s["name"] for s in statuses if s.get("recording")}
    channels = _call(cfg.describe_delivery_channels)["DeliveryChannels"]
    fields = ("name", "roleARN", "recordingGroup", "recordingMode")

    def _restore() -> None:
        now = _recorders()
        for r in now:
            _call(lambda n=r["name"]: cfg.stop_configuration_recorder(ConfigurationRecorderName=n))
        kept = {c["name"] for c in channels}
        for c in _call(cfg.describe_delivery_channels)["DeliveryChannels"]:
            if c["name"] not in kept:
                _call(lambda n=c["name"]: cfg.delete_delivery_channel(DeliveryChannelName=n))
        kept = {r["name"] for r in recorders}
        for r in now:
            if r["name"] not in kept:
                _call(lambda n=r["name"]: cfg.delete_configuration_recorder(ConfigurationRecorderName=n))
        for r in recorders:
            body = {k: v for k, v in r.items() if k in fields}
            _call(lambda b=body: cfg.put_configuration_recorder(ConfigurationRecorder=b))
        for c in channels:
            _call(lambda c=c: cfg.put_delivery_channel(DeliveryChannel=c))
        for r in recorders:
            if r["name"] in recording:
                _call(lambda n=r["name"]: cfg.start_configuration_recorder(ConfigurationRecorderName=n))

    ctx.on_cleanup(_restore)



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
