"""worker-configuration-delete-removes-resource."""
from __future__ import annotations

import base64
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "worker-configuration-delete-removes-resource"
GROUP = "state"
SERVICES = ["kafkaconnect"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteWorkerConfiguration removes it: an independent DescribeWorkerConfiguration then
    raises NotFoundException, a mutation on the dead ARN (TagResource) is rejected the same
    way, and the freed name is reusable for a fresh CreateWorkerConfiguration."""
    kc = ctx.client("kafkaconnect")

    def _props():
        return base64.b64encode(
            b"key.converter=org.apache.kafka.connect.storage.StringConverter\n"
            b"value.converter=org.apache.kafka.connect.storage.StringConverter\n"
        ).decode()

    name = ctx.unique_name("sim2real-kc-workercfg-")
    wc_arn = kc.create_worker_configuration(name=name, propertiesFileContent=_props())[
        "workerConfigurationArn"
    ]
    ctx.on_cleanup(lambda: _delete_if_present(kc, wc_arn))

    kc.delete_worker_configuration(workerConfigurationArn=wc_arn)

    final_code, final_message = _wait_for_error(
        lambda: kc.describe_worker_configuration(workerConfigurationArn=wc_arn),
        timeout_s=120,
        interval_s=3,
    )
    assert final_code == "NotFoundException", final_code
    assert final_message == "Invalid parameter workerConfigurationArn: The requested resource doesn\u2019t exist.", final_message

    # A mutation on the dead ARN must be rejected the same way an independent read is.
    tag_code, tag_message = _client_error(
        lambda: kc.tag_resource(resourceArn=wc_arn, tags={"probe": "dead-arn"})
    )
    assert tag_code == "NotFoundException", (
        f"TagResource on a deleted worker configuration ARN: expected NotFoundException, got {tag_code}"
    )
    assert tag_message == "Resource was not found", tag_message

    # The freed name is reusable: a fresh create under the same name must succeed.
    recreated = kc.create_worker_configuration(name=name, propertiesFileContent=_props())
    recreated_arn = recreated["workerConfigurationArn"]
    ctx.on_cleanup(lambda: _delete_if_present(kc, recreated_arn))
    assert recreated_arn != wc_arn, "recreating under the freed name must mint a new ARN, not resurrect the old one"
    assert recreated["workerConfigurationState"] == "ACTIVE", recreated["workerConfigurationState"]
    described = kc.describe_worker_configuration(workerConfigurationArn=recreated_arn)
    assert described["name"] == name, described["name"]


def _delete_if_present(kc, wc_arn):
    try:
        kc.delete_worker_configuration(workerConfigurationArn=wc_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NotFoundException":
            raise


def _client_error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises, so an
    emulator that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


def _wait_for_error(fn, *, timeout_s=60.0, interval_s=2.0):
    """Re-call fn() until it raises a ClientError and return its (code, message); raise if it
    still succeeds when the budget runs out."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = fn()
        except ClientError as e:
            return e.response["Error"]["Code"], e.response["Error"].get("Message")
        time.sleep(interval_s)
    raise AssertionError(f"the call still succeeded after {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
