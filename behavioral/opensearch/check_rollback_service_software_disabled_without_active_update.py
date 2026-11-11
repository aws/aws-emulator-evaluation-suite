"""rollback-service-software-disabled-without-active-update."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "rollback-service-software-disabled-without-active-update"
GROUP = "error-semantics"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RollbackServiceSoftwareUpdate on a settled domain with no service-software update in progress
    answers 200 and declines in the payload (RollbackAvailable False, exact Description), leaving
    UpdateStatus unchanged; the same call on a never-created domain is ResourceNotFoundException."""
    client = ctx.client("opensearch")
    domain_name, _status = _create_minimal_domain(ctx)
    software_before, response = _rollback_once_settled(ctx, client, domain_name)
    rollback_options = response.get("RollbackServiceSoftwareOptions", {})
    assert rollback_options.get("RollbackAvailable") is False, (
        f"expected RollbackAvailable=False with no update in progress, got {rollback_options!r}"
    )
    assert rollback_options.get("Description") == (
        "No previous software version available for rollback. Please contact AWS Support for "
        "assistance."
    ), f"unexpected rollback decline description: {rollback_options.get('Description')!r}"

    missing_name = ctx.unique_name("sim2real-miss-")
    code_missing, message_missing = _error(
        lambda: client.rollback_service_software_update(DomainName=missing_name)
    )
    assert code_missing == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a domain that was never created, got {code_missing!r}"
    )
    assert message_missing == f"Domain not found: {missing_name}", (
        f"unexpected not-found message: {message_missing!r}"
    )

    status_after = client.describe_domain(DomainName=domain_name)["DomainStatus"]
    software_after = status_after["ServiceSoftwareOptions"]
    assert software_after.get("UpdateStatus") == software_before.get("UpdateStatus"), (
        f"ServiceSoftwareOptions.UpdateStatus changed despite the rollback attempt: "
        f"{software_before!r} -> {software_after!r}"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


_IN_PROGRESS = (
    "A change/update is in progress. Please wait for it to complete before requesting another change."
)


def _quiescent(status):
    """True when DescribeDomain reports no change running on the domain."""
    return (
        status.get("Processing") is False
        and status.get("UpgradeProcessing") is not True
        and status.get("DomainProcessingStatus", "Active") == "Active"
    )


def _rollback_once_settled(ctx, client, name):
    """Poll until the domain is quiescent, then call RollbackServiceSoftwareUpdate; AWS keeps
    post-create work running behind Processing=False and refuses with its exact "change/update is
    in progress" message, so that refusal is polled past. Returns (ServiceSoftwareOptions read just
    before the accepted call, the response)."""
    from botocore.exceptions import ClientError

    budget = _budget_s(ctx, 300.0)
    deadline = time.monotonic() + budget
    last = None
    while True:
        status = client.describe_domain(DomainName=name)["DomainStatus"]
        if _quiescent(status):
            try:
                return status["ServiceSoftwareOptions"], client.rollback_service_software_update(DomainName=name)
            except ClientError as exc:
                error = exc.response["Error"]
                if error.get("Code") != "ValidationException" or error.get("Message") != _IN_PROGRESS:
                    raise AssertionError(
                        "expected a 200 declining the rollback on a settled domain, got "
                        f"{error.get('Code')!r}: {error.get('Message')!r}"
                    ) from exc
                last = error.get("Message")
        else:
            last = {k: status.get(k) for k in ("Processing", "UpgradeProcessing", "DomainProcessingStatus")}
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"domain {name} quiescent: the run budget ended first; not graded")
            raise AssertionError(f"domain {name} still had a change in progress after {budget}s: {last!r}")
        time.sleep(2)


def _create_minimal_domain(ctx):
    client = ctx.client("opensearch")
    name = ctx.unique_name("sim2real-osd-")
    account = ctx.client("sts").get_caller_identity()["Account"]
    client.create_domain(
        DomainName=name,
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        AccessPolicies=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                        "Action": "es:*",
                        "Resource": f"arn:aws:es:{ctx.region}:{account}:domain/{name}/*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: client.delete_domain(DomainName=name))
    deadline = time.monotonic() + _budget_s(ctx, 1800.0)
    status = None
    while True:
        status = client.describe_domain(DomainName=name)["DomainStatus"]
        if status.get("Created") and not status.get("Processing"):
            return name, status
        if time.monotonic() >= deadline:
            break
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"domain {name} active: the run budget ended first; not graded")
    raise AssertionError(f"domain {name} did not become active within budget: {status}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
