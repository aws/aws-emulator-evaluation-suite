"""create-identity-source-invalid-instance-arn-pattern-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-identity-source-invalid-instance-arn-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["mpa"]
MANAGEMENT_ACCOUNT_ONLY = "Action can only be performed by an organization\u2019s management account."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateIdentitySource from a non-management account is refused with AccessDeniedException
    before InstanceArn shape validation, for both a malformed and a well-formed nonexistent
    InstanceArn, and no identity source is created either way."""
    # MPA is a single-Region service: it only operates in us-east-1, regardless of
    # the suite's default Region.
    mpa = ctx.client("mpa", region="us-east-1")

    # positive control: the MPA control plane is otherwise reachable and functional
    # from this caller -- only CreateIdentitySource's org-membership gate is denied.
    baseline = mpa.list_identity_sources(MaxResults=20)
    assert "IdentitySources" in baseline, (
        f"expected ListIdentitySources to succeed and return an IdentitySources "
        f"field, got keys: {sorted(baseline.keys())}"
    )

    malformed_arn = (
        "not-an-arn-at-all-but-long-enough-to-clear-any-client-side-length-check"
    )
    code1, unexpected1 = _try_create(mpa, malformed_arn, ctx.region)
    if unexpected1 is not None:
        ctx.on_cleanup(lambda: _delete_identity_source(mpa, unexpected1["IdentitySourceArn"]))
        raise AssertionError(
            f"expected AccessDeniedException for a malformed InstanceArn from a "
            f"non-management-account caller, but the call unexpectedly succeeded: "
            f"{unexpected1}"
        )
    assert code1 == ("AccessDeniedException", MANAGEMENT_ACCOUNT_ONLY), code1

    good_arn = f"arn:aws:sso:::instance/ssoins-{uuid.uuid4().hex[:16]}"
    code2, unexpected2 = _try_create(mpa, good_arn, ctx.region)
    if unexpected2 is not None:
        ctx.on_cleanup(
            lambda: _delete_identity_source(mpa, unexpected2["IdentitySourceArn"])
        )
        raise AssertionError(
            f"expected AccessDeniedException from a non-management-account "
            f"caller, but CreateIdentitySource unexpectedly succeeded: {unexpected2}"
        )
    assert code2 == ("AccessDeniedException", MANAGEMENT_ACCOUNT_ONLY), code2

    # effect absent: an independent read at the destination -- neither attempted
    # InstanceArn was ever wired into an identity source.
    attempted_instance_arns = {malformed_arn, good_arn}
    wired_instance_arns = {
        src["IdentitySourceParameters"]["IamIdentityCenter"]["InstanceArn"]
        for src in _list_all_identity_sources(mpa)
    }
    overlap = attempted_instance_arns & wired_instance_arns
    assert not overlap, (
        f"expected neither attempted InstanceArn to be wired into any identity "
        f"source after both CreateIdentitySource calls were denied, but found: {overlap}"
    )


# ===== helpers =====
def _list_all_identity_sources(mpa):
    sources = []
    token = None
    while True:
        page_kwargs = {"MaxResults": 20}
        if token:
            page_kwargs["NextToken"] = token
        resp = mpa.list_identity_sources(**page_kwargs)
        sources.extend(resp.get("IdentitySources", []))
        token = resp.get("NextToken")
        if not token:
            break
    return sources


def _try_create(mpa, instance_arn, region):
    try:
        return None, mpa.create_identity_source(
            IdentitySourceParameters={
                "IamIdentityCenter": {"InstanceArn": instance_arn, "Region": region}
            }
        )
    except ClientError as e:
        return (e.response["Error"]["Code"], e.response["Error"].get("Message")), None


def _delete_identity_source(mpa, arn):
    """Teardown: only ResourceNotFoundException means already gone; anything else raises."""
    try:
        mpa.delete_identity_source(IdentitySourceArn=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
