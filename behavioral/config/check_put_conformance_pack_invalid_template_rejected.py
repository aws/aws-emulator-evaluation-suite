"""put-conformance-pack-invalid-template-rejected."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-conformance-pack-invalid-template-rejected"
GROUP = "data-plane"
SERVICES = ["config"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutConformancePack rejects a non-CloudFormation template with
    ConformancePackTemplateValidationException and leaves no pack behind, while a valid template is
    accepted, listed by DescribeConformancePacks and then removable (NoSuchConformancePackException)."""
    config = ctx.client("config")

    bad_pack_name = ctx.unique_name("sim2real-bad-cpack-")
    # Defensive: if an over-permissive target accepts this call, the pack it creates
    # must still be reaped even though the assertion below aborts the check.
    ctx.on_cleanup(lambda: _delete_conformance_pack(config, bad_pack_name))
    code, message = _expect_error(
        lambda: config.put_conformance_pack(
            ConformancePackName=bad_pack_name, TemplateBody="this: is not: a valid: CFN template???"
        )
    )
    assert code == "ConformancePackTemplateValidationException", (
        f"expected ConformancePackTemplateValidationException, got {code!r}"
    )
    assert message == "Template passed in the input parameter is invalid", message

    # Effect absent: no conformance pack was created for the rejected name.
    existing_names = _list_all_conformance_pack_names(config)
    assert bad_pack_name not in existing_names, (
        f"{bad_pack_name} should not exist after a rejected PutConformancePack, saw {existing_names!r}"
    )

    # Positive control: a syntactically valid template with the same shape succeeds.
    good_pack_name = ctx.unique_name("sim2real-good-cpack-")
    rule_name = ctx.unique_name("sim2real-good-cpack-rule-")
    good_template = f"""Resources:
  Sim2RealProcessCheck:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: {rule_name}
      Source:
        Owner: AWS
        SourceIdentifier: AWS_CONFIG_PROCESS_CHECK
"""
    resp = config.put_conformance_pack(
        ConformancePackName=good_pack_name,
        TemplateBody=good_template,
        Tags=[{"Key": "sim2real-behav-check", "Value": CHECK}],
    )
    assert resp["ConformancePackArn"], (
        f"expected a ConformancePackArn in the response, got {resp!r}"
    )
    ctx.on_cleanup(lambda: _delete_conformance_pack(config, good_pack_name))

    # Independent read at the destination: the accepted pack is visible by name.
    _poll_until(
        lambda: _list_all_conformance_pack_names(config),
        lambda names: good_pack_name in names,
        timeout_s=60,
        interval_s=3,
    )

    # PutConformancePack kicks off an async deploy workflow; DeleteConformancePack
    # rejects with ResourceInUseException while it is still running, so wait for a
    # terminal state (either one -- deployment success is not this check's claim)
    # before deleting.
    _poll_until(
        lambda: _conformance_pack_state(config, good_pack_name),
        lambda s: s in ("CREATE_COMPLETE", "CREATE_FAILED"),
        timeout_s=90,
        interval_s=3,
    )

    # Delete proves gone: an independent read must specifically 404 afterward.
    _delete_conformance_pack(config, good_pack_name)
    gone = _poll_until(
        lambda: _probe_error_code(
            lambda: config.describe_conformance_packs(ConformancePackNames=[good_pack_name])
        ),
        lambda e: e[0] == "NoSuchConformancePackException",
        timeout_s=180,
        interval_s=5,
    )
    gone_code, gone_message = gone
    assert gone_code == "NoSuchConformancePackException", (
        f"expected NoSuchConformancePackException after delete, got {gone_code!r}"
    )
    assert gone_message == (
        f"No such conformance pack exists. Conformance Pack(s): [{good_pack_name}]"
    ), gone_message


# ===== helpers =====


def _expect_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because an
    over-permissive target accepting input AWS refuses is a failure in its own right, not a code
    mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _probe_error_code(fn):
    """Call fn(); return its botocore error (code, message), or ("succeeded", response) while
    it still succeeds. Polls a delete propagating; the poll that uses it raises on timeout."""
    try:
        resp = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    return "succeeded", resp


def _conformance_pack_state(config, pack_name):
    details = config.describe_conformance_pack_status(ConformancePackNames=[pack_name]).get(
        "ConformancePackStatusDetails", []
    )
    return details[0]["ConformancePackState"] if details else None


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _list_all_conformance_pack_names(config):
    names = []
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = config.describe_conformance_packs(**kwargs)
        names.extend(p["ConformancePackName"] for p in resp.get("ConformancePackDetails", []))
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return names


def _delete_conformance_pack(config, pack_name):
    deadline = time.monotonic() + 120
    while True:
        try:
            config.delete_conformance_pack(ConformancePackName=pack_name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NoSuchConformancePackException":
                return
            if code != "ResourceInUseException" or time.monotonic() > deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
