"""index-invalid-name-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "index-invalid-name-rejected"
GROUP = "state-machine"
SERVICES = ["opensearch"]


# The IndexName pattern AWS quotes back in its refusal (measured live).
_INDEX_NAME_PATTERN = '^(?!\\.\\.?$)[^_ ,:"+/*\\\\|?#><A-Z-][^ ,:"+/*\\\\|?#><A-Z]*$'
_INVALID_UPPER_MESSAGE = (
    "1 validation error detected: Value 'INVALID_UPPER' at 'indexName' failed to satisfy "
    "constraint: Member must satisfy regular expression pattern: " + _INDEX_NAME_PATTERN
)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateIndex rejects an IndexName that violates the documented naming
    pattern (uppercase characters are disallowed) with ValidationException."""
    aos = ctx.client("opensearch")
    name = _create_minimal_domain(ctx)
    _wait_domain_active(ctx, name, timeout_s=2400.0)

    bad_schema = {"mappings": {"properties": {}}, "settings": {}}
    code, message = _error(
        lambda: aos.create_index(DomainName=name, IndexName="INVALID_UPPER", IndexSchema=bad_schema)
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert message == _INVALID_UPPER_MESSAGE, f"unexpected CreateIndex refusal message: {message!r}"

    # effect is absent: the rejected name never became a real index, proved via an
    # independent read rather than trusting CreateIndex's own refusal.
    absent_code, absent_message = _error(
        lambda: aos.get_index(DomainName=name, IndexName="INVALID_UPPER")
    )
    assert absent_code == "ValidationException", (
        f"index should not have been created after the rejected CreateIndex call: {absent_code!r}"
    )
    assert absent_message == _INVALID_UPPER_MESSAGE, f"unexpected GetIndex message: {absent_message!r}"

    # A syntactically valid name must still succeed against the same domain, proving
    # the rejection above was about the name pattern and not the domain/schema.
    # NOTE: use a "keyword" field (not "text") here -- CreateIndex's automatic semantic
    # enrichment feature targets text fields, and it isn't supported on every engine
    # version (including the one pinned above for fast provisioning). A keyword mapping
    # exercises the same create-index success path without depending on that feature.
    good_resp = aos.create_index(
        DomainName=name,
        IndexName="sim2real-valid-idx",
        IndexSchema={"mappings": {"properties": {"f": {"type": "keyword"}}}, "settings": {}},
    )
    assert good_resp["Status"] == "CREATED"
    ctx.on_cleanup(lambda: _safe_delete_index(ctx, name, "sim2real-valid-idx"))

    # terminal assertion is an independent read at the destination (GetIndex), not the
    # mutating CreateIndex call's own response.
    fetched = aos.get_index(DomainName=name, IndexName="sim2real-valid-idx")
    assert fetched["IndexSchema"] is not None, "valid index not visible via independent GetIndex read"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _error(fn):
    """Call fn(); return its botocore (error code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_minimal_domain(ctx, engine_version=None):
    aos = ctx.client("opensearch")
    sts = ctx.client("sts")
    name = ctx.unique_name("sim2real-osb2-")
    account_id = sts.get_caller_identity()["Account"]
    policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "es:*",
            "Resource": f"arn:aws:es:{ctx.region}:{account_id}:domain/{name}/*",
        }],
    })
    kwargs = dict(
        DomainName=name,
        # CreateIndex/UpdateIndex (used later in this check) are validated against the
        # domain's software version -- OpenSearch_2.13 (previously pinned here purely for
        # fast provisioning) rejects them outright with "Automatic Semantic Enrichment
        # feature is not supported on this software version", regardless of field types.
        # Use the newest available engine version instead, which does support the index
        # management API.
        EngineVersion=engine_version or _pick_latest_opensearch_version(ctx),
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        AccessPolicies=policy,
        TagList=[{"Key": "sim2real", "Value": CHECK}],
    )
    aos.create_domain(**kwargs)
    ctx.on_cleanup(lambda: _safe_delete_domain(ctx, name))
    return name


def _pick_latest_opensearch_version(ctx):
    aos = ctx.client("opensearch")
    versions: list[str] = []
    resp = aos.list_versions(MaxResults=100)
    versions.extend(resp.get("Versions", []))
    while resp.get("NextToken"):
        resp = aos.list_versions(MaxResults=100, NextToken=resp["NextToken"])
        versions.extend(resp.get("Versions", []))

    def key(v):
        try:
            major, minor = v.split("_", 1)[1].split(".")
            return (int(major), int(minor))
        except Exception:
            return (0, 0)

    os_versions = sorted((v for v in versions if v.startswith("OpenSearch_")), key=key)
    return os_versions[-1] if os_versions else None



def _safe_delete_domain(ctx, name):
    aos = ctx.client("opensearch")
    try:
        aos.delete_domain(DomainName=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_index(ctx, domain_name, index_name):
    aos = ctx.client("opensearch")
    try:
        aos.delete_index(DomainName=domain_name, IndexName=index_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_domain_active(ctx, name, timeout_s=2400.0):
    aos = ctx.client("opensearch")

    def probe():
        # DescribeDomain can be throttled fairly aggressively when polled every few seconds
        # over a long domain-creation wait (especially with several checks running against
        # the same account/region concurrently) -- botocore's own default retrying (5
        # attempts, short backoff) isn't enough headroom and surfaces as a bare
        # ThrottlingException ("reached max retries: 5"). Back off ourselves on top of it.
        deadline = time.monotonic() + 120.0
        interval = 5.0
        while True:
            try:
                return aos.describe_domain(DomainName=name)["DomainStatus"]
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code")
                if code == "ThrottlingException" and time.monotonic() < deadline:
                    time.sleep(interval)
                    interval = min(interval * 2, 30.0)
                    continue
                raise

    def done(s):
        return bool(s.get("Created")) and not s.get("Processing")

    return _poll_until(probe, done, timeout_s=timeout_s, interval_s=20.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
