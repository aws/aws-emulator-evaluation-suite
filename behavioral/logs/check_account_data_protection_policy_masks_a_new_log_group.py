"""account-data-protection-policy-masks-a-new-log-group."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "account-data-protection-policy-masks-a-new-log-group"
GROUP = 'data-protection'
SERVICES = ['logs']

_EMAIL = "jane.doe@example.com"
_MASKED_MARKER = "*"
_SENSITIVE_PREFIX = "contact "
_IDENTIFIER_ARN = "arn:aws:dataprotection::aws:data-identifier/EmailAddress"


# ===== helpers =====
def _now_ms() -> int:
    return int(time.time() * 1000)


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


# ===== end helpers =====


def _policy_document(name):
    return json.dumps(
        {
            "Name": name,
            "Version": "2021-06-01",
            "Statement": [
                {
                    "Sid": "audit-email",
                    "DataIdentifier": [_IDENTIFIER_ARN],
                    "Operation": {"Audit": {"FindingsDestination": {}}},
                },
                {
                    "Sid": "mask-email",
                    "DataIdentifier": [_IDENTIFIER_ARN],
                    "Operation": {"Deidentify": {"MaskConfig": {}}},
                },
            ],
        }
    )


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "resource:account-singleton:logs-account-policy")
def run(ctx) -> None:
    """An account-level DATA_PROTECTION_POLICY masks events in a log group created AFTER the policy
    exists and never configured individually; once the account policy is deleted, a further new
    group stores the identical event verbatim, so the account policy is proven to be the cause.
    """
    svc = ctx.client("logs")

    policy_name = ctx.unique_name("sim2real-behav-acctdpp-")
    svc.put_account_policy(
        policyName=policy_name,
        policyDocument=_policy_document(policy_name),
        policyType="DATA_PROTECTION_POLICY",
        scope="ALL",
    )
    deleted = {"done": False}

    def _delete_account_policy(_n=policy_name):
        """Tolerant of absence: the check deletes this policy itself, as the transition
        that establishes the control leg."""
        if deleted["done"]:
            return
        try:
            svc.delete_account_policy(policyName=_n, policyType="DATA_PROTECTION_POLICY")
        except svc.exceptions.ResourceNotFoundException:
            pass

    ctx.on_cleanup(_delete_account_policy)

    # --- The governed group is created AFTER the account policy and is never given a
    # policy of its own. That is the whole property.
    governed = ctx.unique_name("sim2real-behav-lg-acctgov-")
    svc.create_log_group(logGroupName=governed, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=governed: svc.delete_log_group(logGroupName=_n))
    stream = ctx.unique_name("sim2real-behav-stream-")
    svc.create_log_stream(logGroupName=governed, logStreamName=stream)

    def _canary(group, canary_stream):
        def _probe():
            svc.put_log_events(
                logGroupName=group,
                logStreamName=canary_stream,
                logEvents=[{"timestamp": _now_ms(), "message": f"canary {_EMAIL} canary"}],
            )
            resp = svc.get_log_events(
                logGroupName=group, logStreamName=canary_stream, startFromHead=True
            )
            return [e["message"] for e in resp.get("events", [])]

        return _probe

    governed_canary = ctx.unique_name("sim2real-behav-canary-")
    svc.create_log_stream(logGroupName=governed, logStreamName=governed_canary)
    _poll_until(
        _canary(governed, governed_canary),
        lambda msgs: any(_EMAIL not in m and _MASKED_MARKER in m for m in msgs),
        timeout_s=180,
        interval_s=5.0,
        description=(
            "the ACCOUNT-level policy becomes live on the ingest path of a log group that has no "
            "policy of its own"
        ),
    )

    original = f"{_SENSITIVE_PREFIX}{_EMAIL} for details"
    benign = f"{_SENSITIVE_PREFIX}the on-call rota for details"
    base = _now_ms()
    svc.put_log_events(
        logGroupName=governed,
        logStreamName=stream,
        logEvents=[
            {"timestamp": base, "message": original},
            {"timestamp": base + 1000, "message": benign},
        ],
    )

    def _read(group):
        resp = svc.get_log_events(
            logGroupName=group, logStreamName=stream, startFromHead=True
        )
        return [e["message"] for e in resp.get("events", [])]

    governed_messages = _poll_until(
        lambda: _read(governed),
        lambda msgs: len(msgs) == 2 and _EMAIL not in msgs[0],
        timeout_s=120,
        interval_s=3.0,
        description="the governed group returns both events with the address masked",
    )
    assert _EMAIL not in governed_messages[0], (
        "the account-level policy did not mask a group created after it and never configured "
        f"individually: {governed_messages[0]!r}"
    )
    assert _MASKED_MARKER in governed_messages[0], (
        f"the masked event must contain the mask character {_MASKED_MARKER!r}, got "
        f"{governed_messages[0]!r}"
    )
    assert governed_messages[0].startswith(_SENSITIVE_PREFIX), (
        "the account policy masked more than the identifier -- the surrounding text must survive: "
        f"{governed_messages[0]!r}"
    )
    assert governed_messages[1] == benign, (
        "no over-masking: an event containing no matched identifier must be stored verbatim even "
        f"under an account-wide policy, got {governed_messages[1]!r}"
    )

    # --- The policy this check depends on is the ACCOUNT-scoped one, and it is the one
    # this check created. Paginated: the account is shared over time and another
    # suite's account policies can occupy the first page.
    described = []
    token = None
    while True:
        kwargs = {"policyType": "DATA_PROTECTION_POLICY"}
        if token is not None:
            kwargs["nextToken"] = token
        page = svc.describe_account_policies(**kwargs)
        described.extend(page.get("accountPolicies", []))
        token = page.get("nextToken")
        if not token:
            break
    mine = [p for p in described if p.get("policyName") == policy_name]
    assert len(mine) == 1, (
        f"describe_account_policies does not report exactly the account-level policy this check "
        f"depends on; looked for policyName {policy_name!r} in {described!r}"
    )
    assert mine[0]["policyType"] == "DATA_PROTECTION_POLICY", (
        f"the reported policy is not a DATA_PROTECTION_POLICY: {mine[0]!r}"
    )
    assert mine[0].get("scope") == "ALL", (
        f"an account-level data protection policy has no scope other than ALL, and the service "
        f"reported {mine[0].get('scope')!r}: {mine[0]!r}"
    )

    # --- Control, taken across the policy's DELETION: a further brand-new group, also
    # never configured individually, stores the identical event verbatim.
    svc.delete_account_policy(policyName=policy_name, policyType="DATA_PROTECTION_POLICY")
    deleted["done"] = True

    control = ctx.unique_name("sim2real-behav-lg-acctctl-")
    svc.create_log_group(logGroupName=control, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=control: svc.delete_log_group(logGroupName=_n))
    svc.create_log_stream(logGroupName=control, logStreamName=stream)
    control_canary = ctx.unique_name("sim2real-behav-canary-")
    svc.create_log_stream(logGroupName=control, logStreamName=control_canary)
    _poll_until(
        _canary(control, control_canary),
        lambda msgs: any(_EMAIL in m for m in msgs),
        timeout_s=180,
        interval_s=5.0,
        description=(
            "the account-level policy stops governing the ingest path once deleted, observed on a "
            "group created after the deletion"
        ),
    )

    svc.put_log_events(
        logGroupName=control,
        logStreamName=stream,
        logEvents=[{"timestamp": _now_ms(), "message": original}],
    )
    control_messages = _poll_until(
        lambda: _read(control),
        lambda msgs: len(msgs) == 1,
        timeout_s=120,
        interval_s=3.0,
        description="the control group returns its event",
    )
    assert control_messages == [original], (
        "control: with the account policy deleted, a log group created afterwards and never "
        f"configured individually must store the identical event verbatim, got "
        f"{control_messages!r} for {[original]!r}"
    )

    # The account policy is gone, so nothing about this account outlives the check even
    # if a later cleanup were to fail.
    try:
        svc.delete_account_policy(policyName=policy_name, policyType="DATA_PROTECTION_POLICY")
    except ClientError as exc:
        error = exc.response.get("Error", {})
        assert error.get("Code") == "ResourceNotFoundException", (
            f"deleting the already-deleted account policy reported {exc.response!r}, which is "
            "neither success nor 'already gone'"
        )
        expected_message = "Specified resource does not exists!"
        assert error.get("Message") == expected_message, (
            f"expected the exact message {expected_message!r}, got {error.get('Message')!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
