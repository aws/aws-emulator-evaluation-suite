"""upgrade-domain-incompatible-version-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "upgrade-domain-incompatible-version-rejected"
GROUP = "state-machine"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A check-only UpgradeDomain to an advertised compatible version is accepted, while one to an
    unadvertised version fails with BaseException and its exact message; EngineVersion stays unchanged.
    """
    aos = ctx.client("opensearch")
    name = _create_minimal_domain(ctx)
    status = _wait_domain_active(ctx, name, timeout_s=2400.0)
    current_version = status["EngineVersion"]

    compatible = aos.get_compatible_versions(DomainName=name)["CompatibleVersions"]
    valid_targets: set[str] = set()
    for c in compatible:
        if c["SourceVersion"] == current_version:
            valid_targets.update(c.get("TargetVersions", []))
    assert valid_targets, f"no compatible upgrade targets advertised for {current_version}: {compatible}"
    valid_target = sorted(valid_targets)[0]

    # positive control: a genuinely compatible target passes the same eligibility check,
    # so the negative below is provably rejecting this target and not every UpgradeDomain call.
    positive = _error_after_background_tasks(
        lambda: aos.upgrade_domain(DomainName=name, TargetVersion=valid_target, PerformCheckOnly=True)
    )
    assert positive is None, f"expected compatible target {valid_target!r} to be accepted, got {positive}"

    # OpenSearch_1.0 predates every currently supported engine, so it can never be a
    # legitimate forward-upgrade target from a domain running a modern default engine.
    bogus_target = "OpenSearch_1.0"
    assert bogus_target not in valid_targets, f"{bogus_target!r} is advertised as a target: {valid_targets}"
    code_bogus, message_bogus = _error_after_background_tasks(
        lambda: aos.upgrade_domain(DomainName=name, TargetVersion=bogus_target, PerformCheckOnly=True)
    )
    assert code_bogus == "BaseException", (
        f"expected BaseException for unadvertised target {bogus_target!r}, got {code_bogus}"
    )
    expected = f"Failed to submit upgrade. Upgrade from {current_version} to {bogus_target} not supported."
    assert message_bogus == expected, f"expected message {expected!r}, got {message_bogus!r}"

    # effect absent: an independent read confirms neither eligibility check actually
    # moved the domain off its current engine version.
    unchanged = aos.describe_domain(DomainName=name)["DomainStatus"]["EngineVersion"]
    assert unchanged == current_version, f"expected EngineVersion to stay {current_version!r}, got {unchanged!r}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _error_after_background_tasks(fn, *, timeout_s=600.0, interval_s=15.0):
    """``None`` when fn() succeeds, else the error's (code, message). A transient, unmodeled
    (Code == "BaseException") "Domain has background tasks in progress" error is retried
    instead of taken as the final answer -- it is the domain not having fully settled past
    its own Active transition yet, not the refusal the check asserts on."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return None
        except ClientError as e:
            err = e.response["Error"]
            msg = (err.get("Message") or "").lower()
            if err["Code"] == "BaseException" and "background tasks" in msg and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            return err["Code"], err.get("Message")


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
        # Pinning to a known-fast-provisioning engine version instead of letting CreateDomain
        # default to whatever the latest release happens to be: the default has been observed
        # taking noticeably longer to provision, which matters for staying inside the
        # harness's wall-clock budget.
        EngineVersion=engine_version or "OpenSearch_2.13",
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        AccessPolicies=policy,
    )
    aos.create_domain(**kwargs)
    ctx.on_cleanup(lambda: _safe_delete_domain(ctx, name))
    return name



def _safe_delete_domain(ctx, name):
    aos = ctx.client("opensearch")
    try:
        aos.delete_domain(DomainName=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_domain_active(ctx, name, timeout_s=2400.0):
    aos = ctx.client("opensearch")

    def probe():
        return aos.describe_domain(DomainName=name)["DomainStatus"]

    def done(s):
        return bool(s.get("Created")) and not s.get("Processing")

    return _poll_until(probe, done, timeout_s=timeout_s, interval_s=20.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
