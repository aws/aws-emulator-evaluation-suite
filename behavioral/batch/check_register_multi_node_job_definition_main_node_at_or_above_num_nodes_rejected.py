"""register-multi-node-job-definition-main-node-at-or-above-num-nodes-rejected."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-multi-node-job-definition-main-node-at-or-above-num-nodes-rejected"
GROUP = "job-definition"
SERVICES = ["batch"]

# ===== helpers =====

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_IMAGE = "public.ecr.aws/docker/library/busybox:1.36"
_NUM_NODES = 2


def _swallow(fn):
    """Run a teardown call; every error propagates."""
    fn()


def _client_error(fn):
    """Call fn(); return its botocore Error dict and request id. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}), exc.response["ResponseMetadata"].get("RequestId")
    raise AssertionError(
        f"real AWS refuses this RegisterJobDefinition, but it SUCCEEDED and returned {result!r}"
    )


def _node_range(vcpu="1", memory="2048"):
    """One node range covering every node index, with EC2-style container properties."""
    return {
        "targetNodes": f"0:{_NUM_NODES - 1}",
        "container": {
            "image": _IMAGE,
            "command": ["/bin/sh", "-c", "exit 0"],
            "resourceRequirements": [
                {"type": "VCPU", "value": vcpu},
                {"type": "MEMORY", "value": memory},
            ],
        },
    }


def _register_mnp(ctx, bat, *, main_node):
    """RegisterJobDefinition with nodeProperties. Returns (name, response). Raises on refusal."""
    name = ctx.unique_name("sim2real-behav-jd-mnp-")
    resp = bat.register_job_definition(
        jobDefinitionName=name,
        type="multinode",
        nodeProperties={
            "numNodes": _NUM_NODES,
            "mainNode": main_node,
            "nodeRangeProperties": [_node_range()],
        },
        tags=dict(_MANAGED_TAGS),
    )
    rev = resp["revision"]
    ctx.on_cleanup(
        lambda: _swallow(lambda: bat.deregister_job_definition(jobDefinition=f"{name}:{rev}"))
    )
    return name, resp


def _revisions(bat, name):
    """Every revision DescribeJobDefinitions reports for a job-definition NAME, ACTIVE or not."""
    out = []
    token = None
    while True:
        kwargs = {"jobDefinitionName": name, "status": "ACTIVE"}
        if token:
            kwargs["nextToken"] = token
        page = bat.describe_job_definitions(**kwargs)
        out.extend(page.get("jobDefinitions", []))
        token = page.get("nextToken")
        if not token:
            return out


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RegisterJobDefinition rejects multi-node nodeProperties whose mainNode is not fewer than
    numNodes with ClientException and registers no revision, while a legal mainNode succeeds.
    """
    bat = ctx.client("batch")
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account, "STS returned no account id; refusing to run against an unidentified target"

    # --- beat 1: positive control, a legal mainNode registers and round-trips ------------------
    good_name, good_resp = _register_mnp(ctx, bat, main_node=0)
    assert good_resp["revision"] >= 1, (
        f"a valid multi-node job definition must be given a revision, got "
        f"{good_resp.get('revision')!r}"
    )
    assert good_resp["jobDefinitionName"] == good_name, (
        f"RegisterJobDefinition must echo the name it was given; asked for {good_name!r}, got "
        f"{good_resp.get('jobDefinitionName')!r}"
    )

    # Independent read at the destination, via a different operation: the node properties
    # must be stored as given, not merely accepted.
    good_revisions = _revisions(bat, good_name)
    assert len(good_revisions) == 1, (
        f"the valid multi-node job definition {good_name!r} must have exactly 1 ACTIVE revision, "
        f"DescribeJobDefinitions reports {len(good_revisions)}: "
        f"{[d.get('revision') for d in good_revisions]}"
    )
    stored = good_revisions[0]["nodeProperties"]
    assert stored["numNodes"] == _NUM_NODES, (
        f"numNodes must round-trip as {_NUM_NODES}, DescribeJobDefinitions reports "
        f"{stored.get('numNodes')!r}"
    )
    assert stored["mainNode"] == 0, (
        f"mainNode must round-trip as 0, DescribeJobDefinitions reports {stored.get('mainNode')!r}"
    )
    ranges = stored["nodeRangeProperties"]
    assert len(ranges) == 1 and ranges[0]["targetNodes"] == f"0:{_NUM_NODES - 1}", (
        f"the one node range must round-trip covering every index 0:{_NUM_NODES - 1}, got "
        f"{[r.get('targetNodes') for r in ranges]}"
    )

    # --- beat 2: break exactly one field. mainNode == numNodes is out of range by 1 ------------
    # mainNode is a plain Integer in the model with no range trait, so the refusal is server-side;
    # multi-node parallel requires type="multinode", which is why both calls use it.
    bad_name = ctx.unique_name("sim2real-behav-jd-mnp-bad-")
    err, request_id = _client_error(
        lambda: bat.register_job_definition(
            jobDefinitionName=bad_name,
            type="multinode",
            nodeProperties={
                "numNodes": _NUM_NODES,
                "mainNode": _NUM_NODES,  # the ONLY difference from the accepted call above
                "nodeRangeProperties": [_node_range()],
            },
            tags=dict(_MANAGED_TAGS),
        )
    )

    # --- beat 3: the SPECIFIC error code, and a message tight enough to be attributable --------
    assert err.get("Code") == "ClientException", (
        f"mainNode={_NUM_NODES} with numNodes={_NUM_NODES} must be refused with ClientException, "
        f"got Code={err.get('Code')!r} Message={err.get('Message')!r}"
    )
    # Batch embeds the call's own request id in this message.
    expected = (
        "Error executing request, Exception : Main node index is out of range, must be less than "
        f"numNodes., RequestId: {request_id}"
    )
    assert err.get("Message") == expected, f"expected {expected!r}, got {err.get('Message')!r}"
    message = (err.get("Message") or "").lower()
    assert "mainnode" in message or "main node" in message, (
        f"the refusal must name the field it refused, so a generic 400 cannot pass for this "
        f"specific validation; expected 'mainNode' in the message, got {err.get('Message')!r}"
    )

    # --- beat 4: the effect is absent, read independently -------------------------------------
    assert _revisions(bat, bad_name) == [], (
        f"a refused RegisterJobDefinition must create no revision, but "
        f"DescribeJobDefinitions(jobDefinitionName={bad_name!r}) returned "
        f"{[d.get('revision') for d in _revisions(bat, bad_name)]}"
    )

    # And the accepted definition is still there afterwards, so the refusal did not take out the
    # control: the two names must not have been conflated.
    for i in range(3):
        still = _revisions(bat, good_name)
        assert len(still) == 1 and still[0]["nodeProperties"]["mainNode"] == 0, (
            f"read {i + 1} of 3: the refused call must not have disturbed the accepted job "
            f"definition {good_name!r}; DescribeJobDefinitions now reports "
            f"{[(d.get('revision'), d.get('nodeProperties', {}).get('mainNode')) for d in still]}"
        )
        time.sleep(1)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
