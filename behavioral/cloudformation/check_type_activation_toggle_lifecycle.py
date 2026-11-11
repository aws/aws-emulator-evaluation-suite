"""type-activation-toggle-lifecycle."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "type-activation-toggle-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ActivateType on a public third-party RESOURCE type under an alias yields a PRIVATE copy named
    by the alias and listed as ACTIVATED; DeactivateType keeps it describable by the same Arn but flips DeprecatedStatus to
    DEPRECATED and drops it from the ACTIVATED listing."""
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")

    candidate = _pick_public_third_party_type(cfn)
    if candidate is None:
        raise AssertionError("no public third-party RESOURCE extensions available to activate")

    # ActivateType rejects a third-party RESOURCE type with CFNRegistryException ("Please
    # provide execution role to activate the Resource type") without an ExecutionRoleArn.
    # Activation never invokes a handler, so a trust-only role with no permissions suffices.
    role_name = ctx.unique_name("sim2real-cfn-type-exec-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "resources.cloudformation.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _best_effort_delete_role(iam, role_name))

    # A per-run TypeNameAlias gives this run its own private copy of the public type.
    alias = f"Sim2Real::Alias{uuid.uuid4().hex[:12]}::Toggle"
    activated = _activate_with_retry(cfn, candidate, role_arn, alias)
    arn = activated["Arn"]
    ctx.on_cleanup(lambda: _best_effort_deactivate(cfn, arn))

    described = cfn.describe_type(Arn=arn)
    # DescribeType by the private activation Arn has no "IsActivated" field (only the public
    # extension does); Visibility=="PRIVATE" marks the account's activated copy.
    assert described["Visibility"] == "PRIVATE", (
        f"expected Visibility='PRIVATE' for the activated type, got {described['Visibility']!r}"
    )
    assert described["TypeName"] == alias, (
        f"expected DescribeType TypeName to be the alias {alias!r}, got {described['TypeName']!r}"
    )
    assert described.get("OriginalTypeName") == candidate["TypeName"], (
        f"expected OriginalTypeName {candidate['TypeName']!r}, got {described.get('OriginalTypeName')!r}"
    )

    _assert_appears_in_activated_list(cfn, arn)

    cfn.deactivate_type(Arn=arn)
    # DeactivateType does not delete the private registration: DescribeType keeps resolving it.
    # Its effect is DeprecatedStatus=DEPRECATED plus removal from the ACTIVATED listing.
    described_after = cfn.describe_type(Arn=arn)
    assert described_after["DeprecatedStatus"] == "DEPRECATED", (
        f"expected DeprecatedStatus='DEPRECATED' after DeactivateType, got {described_after['DeprecatedStatus']!r}"
    )
    assert not _appears_in_activated_list(cfn, arn), (
        "deactivated type is still present in ListTypes(PRIVATE/ACTIVATED)"
    )


def _pick_public_third_party_type(cfn):
    # ListTypes(PUBLIC, THIRD_PARTY, RESOURCE) is sparse: the first match can sit ~2000 items
    # deep behind empty pages that still return NextToken, so a shallow page budget misses it.
    paginator_kwargs = {
        "Visibility": "PUBLIC",
        "Filters": {"Category": "THIRD_PARTY"},
        "Type": "RESOURCE",
        "MaxResults": 100,
    }
    token = None
    for _ in range(60):
        kwargs = dict(paginator_kwargs)
        if token:
            kwargs["NextToken"] = token
        resp = cfn.list_types(**kwargs)
        for summary in resp.get("TypeSummaries", []):
            if summary.get("TypeName") and summary.get("PublisherId"):
                return summary
        token = resp.get("NextToken")
        if not token:
            break
    return None


def _appears_in_activated_list(cfn, arn: str, max_pages: int = 20) -> bool:
    token = None
    for _ in range(max_pages):
        kwargs = {"Visibility": "PRIVATE", "Filters": {"Category": "ACTIVATED"}, "MaxResults": 100}
        if token:
            kwargs["NextToken"] = token
        resp = cfn.list_types(**kwargs)
        # TypeSummary carries "TypeArn", not the "Arn" key DescribeType uses.
        for summary in resp.get("TypeSummaries", []):
            if summary.get("TypeArn") == arn:
                return True
        token = resp.get("NextToken")
        if not token:
            break
    return False


def _assert_appears_in_activated_list(cfn, arn: str, attempts: int = 3, interval_s: float = 5.0) -> None:
    # ActivateType's own response is not the ACTIVATED-listing's read-your-write guarantee, so
    # retry the bounded scan a few times rather than reading once.
    for attempt in range(1, attempts + 1):
        if _appears_in_activated_list(cfn, arn):
            return
        if attempt < attempts:
            time.sleep(interval_s)
    raise AssertionError(f"activated type {arn} not found in ListTypes(PRIVATE/ACTIVATED) after {attempts} scans")


def _activate_with_retry(cfn, candidate, role_arn: str, alias: str, attempts: int = 6, wait_s: float = 10.0):
    # A just-created IAM role's trust policy is not always immediately visible to
    # ActivateType's own validation, so retry the identical call rather than treating one
    # AccessDenied/CFNRegistryException right after role creation as final.
    last_exc = None
    for attempt in range(1, attempts + 1):
        try:
            return cfn.activate_type(
                Type="RESOURCE",
                TypeName=candidate["TypeName"],
                PublisherId=candidate["PublisherId"],
                TypeNameAlias=alias,
                ExecutionRoleArn=role_arn,
            )
        except ClientError as exc:
            last_exc = exc
            if attempt < attempts:
                time.sleep(wait_s)
    raise AssertionError(f"ActivateType did not succeed after {attempts} attempts: {last_exc}")


def _best_effort_deactivate(cfn, arn: str) -> None:
    try:
        cfn.deactivate_type(Arn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TypeNotFoundException":
            raise


def _best_effort_delete_role(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
