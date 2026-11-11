"""tag-resource-lifecycle."""

from __future__ import annotations

import re
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

_ROLE_ARN_CACHE = None

_DEFAULT_RECORDING_GROUP = {"allSupported": True, "includeGlobalResourceTypes": False}

def _error(fn):
    """Call fn(); return the (code, message) it is refused with. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"expected a rejection, call succeeded with {result!r}")


def _mask_java_identities(message: str) -> str:
    """Mask the Java object identity hashes (``...Tag@3310f8f9``) the service echoes."""
    return re.sub(r"@[0-9a-f]+\b", "@<hash>", message)

def _retry_throttled(fn, attempts=8, base_delay=2.0, retry_codes=("ThrottlingException", "TooManyRequestsException")):
    # Config's control plane has a very low burst limit; churning recorders/rules/
    # delivery-channels across checks reliably trips ThrottlingException. Retry those
    # transparently while re-raising any domain error a check asserts on.
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in retry_codes:
                raise
            last = exc
            time.sleep(base_delay * (2 ** min(attempt, 4)))
    raise last

def _config_slr_arn(ctx):
    """The AWS Config service-linked role's ARN; the check creates it when the account lacks it."""
    iam = ctx.client("iam")
    try:
        return iam.create_service_linked_role(AWSServiceName="config.amazonaws.com")["Role"]["Arn"]
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if err.get("Code") != "InvalidInput" or "has been taken" not in err.get("Message", ""):
            raise
    return iam.get_role(RoleName="AWSServiceRoleForConfig")["Role"]["Arn"]


def _ensure_config_role(ctx):
    """The role ARN for ConfigurationRecorder.roleARN: the AWS Config service-linked role."""
    global _ROLE_ARN_CACHE
    if not _ROLE_ARN_CACHE:
        _ROLE_ARN_CACHE = _config_slr_arn(ctx)
    return _ROLE_ARN_CACHE


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
    # A freshly-created role (see _ensure_config_role) has not necessarily propagated
    # through IAM yet, so Config may transiently refuse it as invalid; bound the wait
    # on that specific error instead of sleeping blind before the first attempt.
    _retry_throttled(
        lambda: cfg.put_configuration_recorder(ConfigurationRecorder=recorder),
        retry_codes=("ThrottlingException", "TooManyRequestsException", "InvalidRoleException"),
    )
    ctx.on_cleanup(
        lambda: _retry_throttled(
            lambda: cfg.delete_configuration_recorder(ConfigurationRecorderName=name)
        )
    )
    return name

CHECK = "tag-resource-lifecycle"
GROUP = 'tagging'
SERVICES = ['config']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """TagResource/ListTagsForResource/UntagResource round-trip correctly on
    a config rule ARN, and exceeding the 50-tag limit in one call is
    rejected rather than silently truncated."""
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    _clear_recorders(ctx)
    recorder_name = ctx.unique_name("sim2real-behav-cfg-recorder-")
    _create_recorder(ctx, recorder_name)

    rule_name = ctx.unique_name("sim2real-behav-cfg-rule-")
    cfg.put_config_rule(
        ConfigRule={"ConfigRuleName": rule_name, "Source": {"Owner": "AWS", "SourceIdentifier": "S3_BUCKET_VERSIONING_ENABLED"}}
    )
    ctx.on_cleanup(lambda a=rule_name: cfg.delete_config_rule(ConfigRuleName=a))

    rule_arn = cfg.describe_config_rules(ConfigRuleNames=[rule_name])["ConfigRules"][0][
        "ConfigRuleArn"
    ]

    cfg.tag_resource(
        ResourceArn=rule_arn,
        Tags=[{"Key": "env", "Value": "test"}, {"Key": "owner", "Value": "fidelity"}],
    )
    tags = {t["Key"]: t["Value"] for t in cfg.list_tags_for_resource(ResourceArn=rule_arn)["Tags"]}
    assert tags.get("env") == "test" and tags.get("owner") == "fidelity", tags

    cfg.untag_resource(ResourceArn=rule_arn, TagKeys=["owner"])
    tags = {t["Key"]: t["Value"] for t in cfg.list_tags_for_resource(ResourceArn=rule_arn)["Tags"]}
    assert "owner" not in tags and tags.get("env") == "test", tags

    too_many = [{"Key": f"k{i}", "Value": "v"} for i in range(51)]
    code, message = _error(lambda: cfg.tag_resource(ResourceArn=rule_arn, Tags=too_many))
    # AWS Config enforces the 50-tag limit as a model/validation constraint and
    # rejects the 51st tag with ValidationException (it has no dedicated
    # TooManyTagsException); the call must be rejected, not truncated.
    assert code == "ValidationException", code
    # The message echoes every tag as a Java object identity ("...Tag@3310f8f9"), which is
    # not derivable from the request; the hashes are masked and the rest is exact.
    echoed = ", ".join(["com.amazonaws.starling.dove.Tag@<hash>"] * len(too_many))
    expected_message = (
        f"1 validation error detected: Value '[{echoed}]' at 'tags' failed to satisfy "
        "constraint: Member must have length less than or equal to 50"
    )
    assert _mask_java_identities(message) == expected_message, (
        f"the refusal said {message[:300]!r}... ({len(message)} chars), expected "
        f"{expected_message[:300]!r}..."
    )

    # Terminal read: independent of the mutating call above, and proves the
    # rejected 51-tag call did not partially apply -- the resource still carries
    # exactly the surviving tag from the untag step, nothing from the refused call.
    tags_after = {t["Key"]: t["Value"] for t in cfg.list_tags_for_resource(ResourceArn=rule_arn)["Tags"]}
    assert tags_after == {"env": "test"}, (
        f"a TagResource call rejected for exceeding the 50-tag limit must leave the "
        f"existing tag set untouched; got {tags_after!r}"
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
