"""op-contract-listPolicies-pagination."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-listPolicies-pagination"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListPolicies with MaxItems=1 truncates and its Marker pages through every policy under the
    path exactly once; a deleted policy drops from the listing and GetPolicy on it fails
    NoSuchEntity with AWS's exact message."""
    iam = ctx.client("iam")
    prefix = ctx.unique_name("sim2real-lp")
    path = f"/{prefix}/"
    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::example-bucket/*"}],
        }
    )

    policy_arns = []
    for i in range(3):
        name = ctx.unique_name(f"sim2real-policy-{i}-")
        arn = iam.create_policy(
            PolicyName=name,
            PolicyDocument=policy_doc,
            Path=path,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )["Policy"]["Arn"]
        policy_arns.append(arn)
        ctx.on_cleanup(lambda a=arn: _gone_ok(lambda: iam.delete_policy(PolicyArn=a)))

    _poll_until(
        lambda: iam.list_policies(PathPrefix=path, Scope="Local")["Policies"],
        lambda p: len(p) == len(policy_arns),
        timeout_s=20,
    )

    first_page = iam.list_policies(PathPrefix=path, Scope="Local", MaxItems=1)
    assert len(first_page["Policies"]) == 1, f"expected 1 policy with MaxItems=1, got {first_page['Policies']}"
    assert first_page["IsTruncated"] is True, f"expected IsTruncated=True with 3 policies and MaxItems=1, got {first_page['IsTruncated']}"
    assert "Marker" in first_page and first_page["Marker"], f"expected a non-empty Marker on a truncated page, got {first_page.get('Marker')!r}"

    collected = list(first_page["Policies"])
    marker = first_page["Marker"]
    for _ in range(len(policy_arns) + 2):
        page = iam.list_policies(PathPrefix=path, Scope="Local", MaxItems=1, Marker=marker)
        collected.extend(page["Policies"])
        if not page["IsTruncated"]:
            break
        marker = page["Marker"]
    else:
        raise AssertionError("pagination did not terminate within the expected number of pages")

    collected_arns = {p["Arn"] for p in collected}
    assert collected_arns == set(policy_arns), f"expected {set(policy_arns)}, got {collected_arns}"
    assert len(collected) == len(policy_arns), "pagination returned duplicate or missing entries"

    removed_arn = policy_arns[0]
    iam.delete_policy(PolicyArn=removed_arn)
    remaining = _poll_until(
        lambda: iam.list_policies(PathPrefix=path, Scope="Local")["Policies"],
        lambda p: len(p) == len(policy_arns) - 1,
        timeout_s=20,
    )
    remaining_arns = {p["Arn"] for p in remaining}
    assert removed_arn not in remaining_arns, f"deleted policy {removed_arn} still present in {remaining_arns}"

    code, message = _error_code(lambda: iam.get_policy(PolicyArn=removed_arn))
    assert code == "NoSuchEntity", f"expected NoSuchEntity for GetPolicy on a deleted ARN, got {code!r}"
    expected_message = f"Policy {removed_arn} was not found."
    assert message == expected_message, (
        f"GetPolicy on the deleted ARN must carry AWS's exact message {expected_message!r}; got {message!r}"
    )


def _error_code(fn):
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError("expected a ClientError, call unexpectedly succeeded")


def _poll_until(probe, predicate, *, timeout_s=20.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last result={last!r}")


def _gone_ok(fn):
    """Teardown-only: the body deletes this resource itself, so tolerate it already being gone."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
