"""configuration-delete-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "configuration-delete-lifecycle"
GROUP = 'configuration'
SERVICES = ['kafka']

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _delete_configuration_if_present(msk, arn):
    """Teardown: delete the configuration unless the check already deleted it."""
    try:
        msk.delete_configuration(Arn=arn)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Message") != "Configuration ARN does not exist.":
            raise


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteConfiguration returns DELETING for an ACTIVE configuration, and DescribeConfiguration then
    reports only DELETING until it fails with BadRequestException "Configuration ARN does not exist." for
    good."""
    msk = ctx.client("kafka")
    name = ctx.unique_name("sim2real-behav-config-del-")
    resp = msk.create_configuration(
        Name=name,
        ServerProperties=b"num.partitions=1\n",
        KafkaVersions=["3.6.0"],
    )
    arn = resp["Arn"]
    ctx.on_cleanup(lambda _a=arn: _delete_configuration_if_present(msk, _a))
    assert resp["State"] == "ACTIVE", resp

    del_resp = msk.delete_configuration(Arn=arn)
    assert del_resp["Arn"] == arn, del_resp
    assert del_resp["State"] == "DELETING", f"expected DELETING from delete, got {del_resp['State']}"

    observed: list[tuple] = []

    def probe():
        try:
            value = ("state", msk.describe_configuration(Arn=arn)["State"], None)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            value = ("error", err.get("Code"), err.get("Message"))
        observed.append(value)
        return value

    outcome = _poll_until(
        probe,
        lambda v: v[0] == "error",
        timeout_s=120,
        interval_s=3,
        description="deleted configuration to stop answering DescribeConfiguration",
    )
    assert all(v == ("state", "DELETING", None) or v[0] == "error" for v in observed), (
        f"a deleted configuration may only read DELETING until it stops answering: {observed}"
    )
    assert outcome[1] == "BadRequestException", outcome
    assert outcome[2] == "Configuration ARN does not exist.", outcome

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
