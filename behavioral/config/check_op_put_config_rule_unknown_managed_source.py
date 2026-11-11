"""op-put-config-rule-unknown-managed-source."""

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
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _retry_throttled(fn, attempts=8, base_delay=2.0, extra_codes=()):
    # Config's control plane has a very low burst limit; churning recorders/rules/
    # delivery-channels across checks reliably trips ThrottlingException. Retry those
    # transparently while re-raising any domain error a check asserts on. `extra_codes`
    # lets a caller also retry a specific transient domain error (e.g. IAM role propagation)
    # bounded by the same attempt/backoff budget, instead of an unconditional sleep.
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if (
                code not in ("ThrottlingException", "TooManyRequestsException")
                and code not in extra_codes
            ):
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
            # IAM is eventually consistent, so Config's pass-role validation can fail
            # against a role that was just created; _create_recorder's caller retries
            # PutConfigurationRecorder on InvalidRoleException for exactly this, bounded
            # by _retry_throttled's attempt budget instead of an unconditional sleep.
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
            _retry_throttled(
                lambda n=name: cfg.stop_configuration_recorder(ConfigurationRecorderName=n)
            )
        except Exception:
            pass
        try:
            _retry_throttled(
                lambda n=name: cfg.delete_configuration_recorder(ConfigurationRecorderName=n)
            )
        except Exception:
            pass


def _create_recorder(ctx, name, recording_group=None, role_arn=None):
    cfg = ctx.client("config")
    recorder = {
        "name": name,
        "roleARN": role_arn or _ensure_config_role(ctx),
        "recordingGroup": recording_group or dict(_DEFAULT_RECORDING_GROUP),
    }
    _retry_throttled(
        lambda: cfg.put_configuration_recorder(
            ConfigurationRecorder=recorder,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        ),
        extra_codes=("InvalidRoleException",),
    )
    ctx.on_cleanup(
        lambda: _retry_throttled(
            lambda: cfg.delete_configuration_recorder(ConfigurationRecorderName=name)
        )
    )
    return name


_GOOD_MANAGED_SOURCE_IDENTIFIER = "IAM_USER_NO_POLICIES_CHECK"


def _delete_rule_if_present(cfg, name):
    try:
        _retry_throttled(lambda: cfg.delete_config_rule(ConfigRuleName=name))
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchConfigRuleException":
            raise


CHECK = "op-put-config-rule-unknown-managed-source"
GROUP = "overly-permissive"
SERVICES = ["config"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """PutConfigRule with Owner AWS and an unknown SourceIdentifier fails with
    InvalidParameterValueException and its exact message and leaves no rule, while a real AWS managed
    SourceIdentifier is accepted."""
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    _clear_recorders(ctx)
    recorder_name = ctx.unique_name("sim2real-behav-cfg-recorder-")
    _create_recorder(ctx, recorder_name)

    # Positive control: a real AWS-managed SourceIdentifier is accepted.
    good_rule_name = ctx.unique_name("sim2real-behav-cfg-rule-good-")
    _retry_throttled(
        lambda: cfg.put_config_rule(
            ConfigRule={
                "ConfigRuleName": good_rule_name,
                "Source": {"Owner": "AWS", "SourceIdentifier": _GOOD_MANAGED_SOURCE_IDENTIFIER},
            },
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    )
    ctx.on_cleanup(lambda: _delete_rule_if_present(cfg, good_rule_name))
    good_rules = cfg.describe_config_rules(ConfigRuleNames=[good_rule_name])["ConfigRules"]
    assert (
        len(good_rules) == 1
        and good_rules[0]["Source"]["SourceIdentifier"] == _GOOD_MANAGED_SOURCE_IDENTIFIER
    ), (
        f"the positive control with real AWS-managed SourceIdentifier "
        f"{_GOOD_MANAGED_SOURCE_IDENTIFIER!r} did not register: {good_rules!r}"
    )

    rule_name = ctx.unique_name("sim2real-behav-cfg-rule-")
    code, code_message = _error(
        lambda: cfg.put_config_rule(
            ConfigRule={
                "ConfigRuleName": rule_name,
                "Source": {
                    "Owner": "AWS",
                    "SourceIdentifier": "THIS_MANAGED_RULE_DOES_NOT_EXIST",
                },
            }
        )
    )
    assert code == "InvalidParameterValueException", (
        f"PutConfigRule with an unknown AWS-managed SourceIdentifier returned {code!r}, "
        f'expected "InvalidParameterValueException"'
    )
    assert code_message == (
        "The sourceIdentifier THIS_MANAGED_RULE_DOES_NOT_EXIST is invalid. Please refer to the "
        "documentation for a list of valid sourceIdentifiers that can be used when AWS is the Owner."
    ), code_message

    # nothing must have been persisted
    missing_code, missing_code_message = _error(
        lambda: cfg.describe_config_rules(ConfigRuleNames=[rule_name])
    )
    assert missing_code == "NoSuchConfigRuleException", (
        f"the rejected rule {rule_name!r} was still describable and returned {missing_code!r}, "
        f'expected "NoSuchConfigRuleException"'
    )
    assert missing_code_message == (
        "One or more ConfigRules provided in the request are invalid. Please check the configRule names."
    ), missing_code_message


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
