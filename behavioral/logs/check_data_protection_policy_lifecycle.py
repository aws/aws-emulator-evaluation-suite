"""data-protection-policy-lifecycle."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "data-protection-policy-lifecycle"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutDataProtectionPolicy on a log group is retrievable via GetDataProtectionPolicy and
    removed by DeleteDataProtectionPolicy."""
    logs = ctx.client("logs")
    group_name = ctx.unique_name("sim2real-dpp-")
    logs.create_log_group(logGroupName=group_name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))

    # "SSN" is not a real managed data identifier name; the identifier must be one of the
    # documented managed data identifiers (e.g. "EmailAddress") under the
    # arn:aws:dataprotection::aws:data-identifier/ namespace.
    policy_document = {
        "Name": "sim2real-behav-dpp",
        "Version": "2021-06-01",
        "Statement": [
            {
                "Sid": "audit-email",
                "DataIdentifier": ["arn:aws:dataprotection::aws:data-identifier/EmailAddress"],
                "Operation": {"Audit": {"FindingsDestination": {}}},
            },
            {
                "Sid": "redact-email",
                "DataIdentifier": ["arn:aws:dataprotection::aws:data-identifier/EmailAddress"],
                "Operation": {"Deidentify": {"MaskConfig": {}}},
            },
        ],
    }

    logs.put_data_protection_policy(
        logGroupIdentifier=group_name, policyDocument=json.dumps(policy_document)
    )
    ctx.on_cleanup(lambda: _safe_delete_dpp(logs, group_name))

    got = logs.get_data_protection_policy(logGroupIdentifier=group_name)
    identifier = got["logGroupIdentifier"]
    assert identifier in (group_name, f"log-group:{group_name}") or group_name in identifier, (
        f"expected logGroupIdentifier to reference {group_name!r}, got {identifier!r}"
    )
    round_tripped = json.loads(got["policyDocument"])
    got_sid = round_tripped["Statement"][0]["Sid"]
    assert got_sid == "audit-email", f"expected first statement Sid 'audit-email', got {got_sid!r}"

    logs.delete_data_protection_policy(logGroupIdentifier=group_name)

    # On real AWS, GetDataProtectionPolicy keeps succeeding after the policy is deleted
    # (it does not start raising ResourceNotFoundException) -- it just stops returning a
    # policy document. Poll for that state instead of expecting an exception.
    after = _poll_until(
        lambda: logs.get_data_protection_policy(logGroupIdentifier=group_name),
        lambda resp: not resp.get("policyDocument"),
        timeout_s=30,
        interval_s=2,
    )
    assert not after.get("policyDocument"), f"policy document still present after delete: {after}"


def _safe_delete_dpp(logs, group_name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        logs.delete_data_protection_policy(logGroupIdentifier=group_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
