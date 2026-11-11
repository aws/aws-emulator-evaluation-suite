"""list-type-registrations-chronological-ordering."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "list-type-registrations-chronological-ordering"
GROUP = "ordering"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTypeRegistrations for one TypeName returns each of three FAILED registration tokens exactly
    once across the full paginated listing, with no duplicates; CloudFormation does not order the list by
    submission time, so only completeness is asserted."""
    cfn = ctx.client("cloudformation")
    package_url = _scratch_bucket_with_module_package(ctx)
    type_name = _module_type_name(ctx, "Ord")
    ctx.on_cleanup(lambda: cfn.deregister_type(Type="MODULE", TypeName=type_name))

    submitted_tokens = []
    for _ in range(3):
        token = cfn.register_type(
            Type="MODULE", TypeName=type_name, SchemaHandlerPackage=package_url
        )["RegistrationToken"]
        described = _poll_registration(cfn, token)
        assert described["ProgressStatus"] == "FAILED", f"expected deterministic FAILED, got: {described}"
        submitted_tokens.append(token)

    token_set = set(submitted_tokens)

    def _collect_seen():
        seen = []
        next_token = None
        pages = 0
        while pages < 10:
            kwargs = {
                "TypeName": type_name,
                "Type": "MODULE",
                "RegistrationStatusFilter": "FAILED",
                "MaxResults": 100,
            }
            if next_token:
                kwargs["NextToken"] = next_token
            resp = cfn.list_type_registrations(**kwargs)
            seen.extend(resp.get("RegistrationTokenList", []))
            next_token = resp.get("NextToken")
            pages += 1
            if not next_token:
                break
        return seen

    # The registry listing is eventually consistent immediately after a registration
    # reaches a terminal state, so poll (bounded) until all 3 tokens are visible.
    deadline = time.monotonic() + 60.0
    seen = _collect_seen()
    seen_relevant = [t for t in seen if t in token_set]
    while len(seen_relevant) < len(submitted_tokens) and time.monotonic() < deadline:
        time.sleep(5.0)
        seen = _collect_seen()
        seen_relevant = [t for t in seen if t in token_set]

    # No duplicates anywhere in the full (unfiltered-by-our-set) listing.
    assert len(seen) == len(set(seen)), "ListTypeRegistrations returned a duplicate token"
    # Every one of our 3 submitted registrations appears exactly once.
    assert sorted(seen_relevant) == sorted(submitted_tokens), (
        f"expected the 3 submitted registrations to each appear exactly once, "
        f"submitted={submitted_tokens} seen={seen_relevant}"
    )


def _module_type_name(ctx, tag):
    token = "".join(ch for ch in ctx.unique_name(tag) if ch.isalnum())
    if len(token) < 2:
        token = (token + "abcdefgh")[:8]
    token = token[:40]
    return f"S2R{tag[:6].capitalize()}::{token}::Behav::MODULE"


def _module_fragment_zip():
    fragment = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "sim2real behavioral fidelity test module fragment",
        "Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": {}}},
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("fragments/fragment.json", json.dumps(fragment))
    return buf.getvalue()


def _scratch_bucket_with_module_package(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-cfn-mod-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )

    def _cleanup_bucket():
        try:
            s3.delete_object(Bucket=bucket, Key="module-package.zip")
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise
        try:
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup_bucket)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "simparity-check", "Value": CHECK}]})
    s3.put_object(Bucket=bucket, Key="module-package.zip", Body=_module_fragment_zip())
    return f"s3://{bucket}/module-package.zip"


def _poll_registration(cfn, token, timeout_s=240.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        described = cfn.describe_type_registration(RegistrationToken=token)
        if described["ProgressStatus"] in ("COMPLETE", "FAILED"):
            return described
        time.sleep(interval_s)
    raise AssertionError(f"registration {token} did not reach a terminal state within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
