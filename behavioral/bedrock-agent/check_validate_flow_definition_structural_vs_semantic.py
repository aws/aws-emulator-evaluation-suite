"""validate-flow-definition-structural-vs-semantic."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "validate-flow-definition-structural-vs-semantic"
GROUP = "error-semantics"
SERVICES = ["bedrock-agent"]

_VALID_NODES = [
    {"name": "FlowInputNode", "type": "Input", "outputs": [{"name": "document", "type": "String"}]},
    {
        "name": "FlowOutputNode",
        "type": "Output",
        "inputs": [{"name": "document", "type": "String", "expression": "$.data"}],
    },
]


_UNKNOWN_NODE_TYPE_MESSAGE = (
    "1 validation error detected: Value at 'definition.nodes.1.member.type' failed to satisfy "
    "constraint: Member must satisfy enum value set: [LoopController, Output, Loop, Prompt, Agent, "
    "LoopInput, InlineCode, Input, Collector, Iterator, KnowledgeBase, Retrieval, Storage, "
    "Condition, LambdaFunction, Lex]"
)


_VALID_CONNECTION = {
    "name": "InputToOutput",
    "source": "FlowInputNode",
    "target": "FlowOutputNode",
    "type": "Data",
    "configuration": {"data": {"sourceOutput": "document", "targetInput": "document"}},
}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ValidateFlowDefinition returns empty validations for a valid flow, an Error validation for a
    dangling node reference, and rejects an unknown node type with ValidationException and the exact
    message."""
    bedrock_agent = ctx.client("bedrock-agent")

    fully_valid = {"nodes": _VALID_NODES, "connections": [_VALID_CONNECTION]}
    positive_control = bedrock_agent.validate_flow_definition(definition=fully_valid)
    assert positive_control["validations"] == [], positive_control["validations"]

    structurally_malformed = {
        "nodes": [
            {"name": "FlowInputNode", "type": "NotARealFlowNodeType", "outputs": [{"name": "document", "type": "String"}]},
            _VALID_NODES[1],
        ],
        "connections": [_VALID_CONNECTION],
    }
    code, message = _error(lambda: bedrock_agent.validate_flow_definition(definition=structurally_malformed))
    assert code == "ValidationException", code
    assert message == _UNKNOWN_NODE_TYPE_MESSAGE, message

    semantically_broken_but_well_formed = {
        "nodes": _VALID_NODES,
        "connections": [
            {
                "name": "DanglingConnection",
                "source": "NodeThatDoesNotExist",
                "target": "FlowOutputNode",
                "type": "Data",
                "configuration": {"data": {"sourceOutput": "document", "targetInput": "document"}},
            }
        ],
    }
    result = bedrock_agent.validate_flow_definition(definition=semantically_broken_but_well_formed)
    assert len(result["validations"]) > 0, "expected the dangling reference to surface as a validation finding"
    assert any(v.get("severity") == "Error" for v in result["validations"]), result["validations"]


def _error(fn):
    """Return (Error.Code, Error.Message) of the ClientError fn raises; an unexpected success
    raises, so a target that accepts what AWS refuses fails loudly rather than as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
