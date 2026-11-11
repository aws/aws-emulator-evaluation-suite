"""describe-config-rules-paginates-at-fixed-page-size."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

_CONFIG_TRUST_POLICY = """{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Principal": {"Service": "config.amazonaws.com"}, "Action": "sts:AssumeRole"}
  ]
}"""
_CONFIG_MANAGED_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
_MANAGED_SOURCE_IDENTIFIER = "S3_BUCKET_VERSIONING_ENABLED"
_RULE_COUNT = 27

CHECK = "describe-config-rules-paginates-at-fixed-page-size"
GROUP = "config-rule"
SERVICES = ["config"]


def _retry_throttled(fn, attempts=10, base_delay=2.0):
    # Config's control plane has a very low burst limit; churning this many rules
    # reliably trips ThrottlingException.
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


def _ensure_recorder_exists(ctx):
    """Guarantee a configuration recorder EXISTS without touching one we did not create;
    never start one (account-wide, billed per configuration item)."""
    cfg = ctx.client("config")
    existing = _retry_throttled(cfg.describe_configuration_recorders).get(
        "ConfigurationRecorders", []
    )
    if existing:
        return

    iam = ctx.client("iam")
    created_role = ctx.unique_name("sim2real-behav-cfg-pgrole-")
    role_arn = iam.create_role(
        RoleName=created_role,
        AssumeRolePolicyDocument=_CONFIG_TRUST_POLICY,
        Description="sim2real behavioral fidelity probe role for AWS Config",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=created_role))
    iam.attach_role_policy(RoleName=created_role, PolicyArn=_CONFIG_MANAGED_POLICY_ARN)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=created_role, PolicyArn=_CONFIG_MANAGED_POLICY_ARN)
    )

    recorder = ctx.unique_name("sim2real-behav-cfg-pgrecorder-")
    deadline = time.monotonic() + 120
    last = None
    while time.monotonic() < deadline:
        try:
            _retry_throttled(
                lambda: cfg.put_configuration_recorder(
                    ConfigurationRecorder={
                        "name": recorder,
                        "roleARN": role_arn,
                        "recordingGroup": {
                            "allSupported": False,
                            "resourceTypes": ["AWS::S3::Bucket"],
                        },
                    }
                )
            )
            break
        except ClientError as exc:
            last = exc
            if exc.response.get("Error", {}).get("Code", "") not in (
                "InsufficientPermissionsException",
                "ValidationException",
            ):
                raise
            time.sleep(5)
    else:
        raise AssertionError(f"could not create a configuration recorder within 120s: {last!r}")
    ctx.on_cleanup(
        lambda: _retry_throttled(
            lambda: cfg.delete_configuration_recorder(ConfigurationRecorderName=recorder)
        )
    )


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """DescribeConfigRules caps a page at 25 rules (a server-side constant the model does not
    declare), and the paginator walks every page to recover the full set.
    """
    cfg = ctx.client("config")
    _ensure_recorder_exists(ctx)

    rule_names = [ctx.unique_name(f"sim2real-behav-cfg-pg-{i:03d}-") for i in range(_RULE_COUNT)]
    for name in rule_names:
        _retry_throttled(
            lambda n=name: cfg.put_config_rule(
                ConfigRule={
                    "ConfigRuleName": n,
                    "Source": {"Owner": "AWS", "SourceIdentifier": _MANAGED_SOURCE_IDENTIFIER},
                }
            )
        )
        ctx.on_cleanup(
            lambda n=name: _retry_throttled(lambda: cfg.delete_config_rule(ConfigRuleName=n))
        )

    # ConfigRuleNames is itself capped at 25, so the page boundary is only observable unfiltered;
    # the account holds at least our 27 rules, so the first page must be a full 25 with a NextToken.
    first_page = _retry_throttled(lambda: cfg.describe_config_rules())
    assert len(first_page["ConfigRules"]) == 25, (
        f"expected the first unfiltered page of DescribeConfigRules to be hard-capped at "
        f"25 rules (this check alone created {_RULE_COUNT}), got "
        f"{len(first_page['ConfigRules'])}"
    )
    assert first_page.get("NextToken"), (
        "a full 25-row page with more rules outstanding must carry a NextToken; got "
        f"{first_page.get('NextToken')!r}"
    )

    collected = []
    paginator = cfg.get_paginator("describe_config_rules")
    for page in _retry_throttled(lambda: list(paginator.paginate())):
        page_rules = page["ConfigRules"]
        assert len(page_rules) <= 25, (
            f"every page of DescribeConfigRules must respect the 25-row cap, got "
            f"{len(page_rules)} rules on one page"
        )
        collected.extend(r["ConfigRuleName"] for r in page_rules)

    collected_set = set(collected)
    missing = set(rule_names) - collected_set
    assert not missing, (
        f"paginating through every page must recover every one of the {_RULE_COUNT} rules "
        f"this check created; missing {sorted(missing)!r}"
    )
    ours = [n for n in collected if n in rule_names]
    assert len(ours) == len(set(ours)), (
        f"the paginator returned one of our own rule names more than once across pages: "
        f"{[n for n in set(ours) if ours.count(n) > 1]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
