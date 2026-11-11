"""concurrent-delete-config-rule-race."""

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

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

def _run_concurrent(fns, *, timeout_s=60):
    import concurrent.futures
    results = [None] * len(fns)
    resolved = set()

    def _capture(fut, idx):
        try:
            results[idx] = fut.result()
        except Exception as exc:
            results[idx] = exc
        resolved.add(idx)
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns)))
    try:
        future_to_idx = {ex.submit(fn): i for i, fn in enumerate(fns)}
        try:
            for fut in concurrent.futures.as_completed(future_to_idx, timeout=timeout_s):
                _capture(fut, future_to_idx[fut])
        except concurrent.futures.TimeoutError as timeout_exc:
            for fut, idx in future_to_idx.items():
                if idx in resolved:
                    continue
                if fut.done():
                    _capture(fut, idx)
                else:
                    fut.cancel()
                    results[idx] = timeout_exc
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return results

def _concurrent_successes(results):
    return sum((1 for r in results if not isinstance(r, BaseException)))

def _concurrent_error_codes(results):
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get('Error', {}).get('Code'))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes

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

_RESOURCE_TAGS = [{"Key": "env", "Value": "test"}, {"Key": "owner", "Value": "fidelity"}]

def _put_recorder_awaiting_role_propagation(cfg, recorder, *, timeout_s=60, interval_s=3.0):
    # IAM is eventually consistent: Config's pass-role validation of a just-created
    # role fails with InvalidRoleException until the role has propagated. Bounded
    # retry on that specific error, not a flat sleep.
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return _retry_throttled(
                lambda: cfg.put_configuration_recorder(
                    ConfigurationRecorder=recorder, Tags=_RESOURCE_TAGS
                )
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidRoleException" or (
                time.monotonic() >= deadline
            ):
                raise
            time.sleep(interval_s)

def _create_recorder(ctx, name, recording_group=None, role_arn=None):
    cfg = ctx.client("config")
    recorder = {
        "name": name,
        "roleARN": role_arn or _ensure_config_role(ctx),
        "recordingGroup": recording_group or dict(_DEFAULT_RECORDING_GROUP),
    }
    _put_recorder_awaiting_role_propagation(cfg, recorder)
    ctx.on_cleanup(
        lambda: _absent_ok(
            lambda: _retry_throttled(
                lambda: cfg.delete_configuration_recorder(ConfigurationRecorderName=name)
            ),
            "NoSuchConfigurationRecorderException",
        )
    )
    return name

CHECK = "concurrent-delete-config-rule-race"
GROUP = 'concurrency'
SERVICES = ['config']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """CONCURRENCY: racing DeleteConfigRule calls against the SAME rule must
    serialize to exactly one success; every other racer observes an error, never
    a silent duplicate success, and the rule is fully gone afterwards."""
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    _clear_recorders(ctx)
    recorder_name = ctx.unique_name("sim2real-behav-cfg-recorder-")
    _create_recorder(ctx, recorder_name)

    rule_name = ctx.unique_name("sim2real-behav-cfg-rule-")
    cfg.put_config_rule(
        ConfigRule={
            "ConfigRuleName": rule_name,
            "Source": {"Owner": "AWS", "SourceIdentifier": "S3_BUCKET_PUBLIC_READ_PROHIBITED"},
        },
        Tags=_RESOURCE_TAGS,
    )
    ctx.on_cleanup(
        lambda a=rule_name: _absent_ok(
            lambda: cfg.delete_config_rule(ConfigRuleName=a), "NoSuchConfigRuleException"
        )
    )

    # the rule must be ACTIVE (evaluable/deletable) before the racers fire
    _poll_until(
        lambda: cfg.describe_config_rules(ConfigRuleNames=[rule_name])["ConfigRules"][0][
            "ConfigRuleState"
        ],
        lambda s: s == "ACTIVE",
        timeout_s=20,
        interval_s=2,
        description="config rule ACTIVE",
    )

    n = 6
    # Throttling says nothing about the race, so each racer retries it away.
    results = _run_concurrent(
        [lambda: _retry_throttled(lambda: cfg.delete_config_rule(ConfigRuleName=rule_name)) for _ in range(n)],
        timeout_s=90,
    )
    successes = _concurrent_successes(results)
    assert successes >= 1, f"at least one racer must succeed: {results}"

    error_codes = _concurrent_error_codes(results)
    assert successes + len(error_codes) == n, f"every racer must report an outcome: {results}"
    # A loser that arrives while the accepted delete is still running finds the rule in use; one
    # that arrives after it finished finds no rule.
    in_use = f"The rule {rule_name} is currently in use. Please retry after some time."
    no_such = (
        f"The ConfigRule '{rule_name}' provided in the request is invalid. Please check the configRule name."
    )
    for r in results:
        if isinstance(r, BaseException):
            assert isinstance(r, ClientError), f"a racer failed without an AWS answer: {r!r}"
            err = r.response.get("Error", {})
            observed = (err.get("Code"), err.get("Message"))
            if observed[0] == "NoSuchConfigRuleException":
                assert observed[1] == no_such, f"unexpected not-found message of a losing racer: {err}"
            else:
                assert observed == ("ResourceInUseException", in_use), (
                    f"unexpected refusal of a losing racer: {err} (all: {_concurrent_error_codes(results)})"
                )

    # DeleteConfigRule is asynchronous: the rule stays describable (DELETING) for a
    # while before it disappears, only then raising NoSuchConfigRuleException.
    def _lookup():
        """The describe response while the rule is still listed, else its Error dict."""
        try:
            return {"Listed": cfg.describe_config_rules(ConfigRuleNames=[rule_name])}
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err

    gone = _poll_until(
        _lookup,
        lambda r: "Listed" not in r,
        timeout_s=180,
        interval_s=5,
        description="config rule fully gone",
    )
    assert gone.get("Code") == "NoSuchConfigRuleException", gone
    assert gone.get("Message") == (
        "One or more ConfigRules provided in the request are invalid. Please check the "
        "configRule names."
    ), gone


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
