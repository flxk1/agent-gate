from __future__ import annotations

from agent_gate.records import chain_receipt
from agent_gate.records.llm_capture import (
    CaptureResult,
    IngestMode,
    LLMExchange,
    OversightLevel,
    VerbosityLevel,
    capture_llm_exchange,
    decide_verbosity,
    recorded_spend_cents,
)


def test_agentic_capture_is_mandatory_even_at_autonomous():
    v, prompts = decide_verbosity(IngestMode.AGENTIC, OversightLevel.AUTONOMOUS)
    assert v == VerbosityLevel.METADATA
    assert not prompts


def test_interactive_capture_is_silent_at_low_oversight():
    v, prompts = decide_verbosity(IngestMode.INTERACTIVE, OversightLevel.AUTONOMOUS)
    assert v == VerbosityLevel.NONE


def test_oversight_disabled_agentic_captures_max_verbosity_no_prompt():
    v, prompts = decide_verbosity(IngestMode.AGENTIC, OversightLevel.MANUAL, oversight_active=False)
    assert v == VerbosityLevel.FULL_PLUS_TRACE
    assert not prompts


def test_oversight_disabled_interactive_is_silent():
    v, prompts = decide_verbosity(IngestMode.INTERACTIVE, OversightLevel.MANUAL, oversight_active=False)
    assert v == VerbosityLevel.NONE


def test_capture_records_a_signed_chain_event(chain, issuer, trust_store):
    exchange = LLMExchange(model="test-model", prompt_context="hi", response="hello there",
                           cost_estimate_cents=1.5)
    result = capture_llm_exchange(exchange, mode=IngestMode.AGENTIC,
                                  oversight=OversightLevel.APPROVE,
                                  chain=chain, signer=issuer)
    assert isinstance(result, CaptureResult)
    assert result.captured
    assert result.verbosity == VerbosityLevel.FULL
    assert chain_receipt.verify(chain, trust_store=trust_store).ok


def test_secrets_are_redacted_before_capture(chain, issuer):
    exchange = LLMExchange(model="m", prompt_context="my api_key: sk-abcdef1234567890",
                           response="here is the key sk-abcdef1234567890 use it")
    capture_llm_exchange(exchange, mode=IngestMode.AGENTIC, oversight=OversightLevel.MANUAL,
                        chain=chain, signer=issuer)
    payload = chain_receipt.payloads(chain)[-1]
    assert "sk-abcdef1234567890" not in payload["body"]
    assert "sk-abcdef1234567890" not in payload["facets"].get("prompt_context", "")


def test_metadata_verbosity_carries_no_body(chain, issuer):
    exchange = LLMExchange(model="m", prompt_context="hi", response="a secret answer")
    capture_llm_exchange(exchange, mode=IngestMode.AGENTIC, oversight=OversightLevel.AUTONOMOUS,
                        chain=chain, signer=issuer)
    payload = chain_receipt.payloads(chain)[-1]
    assert payload["body"] == ""


def test_recorded_spend_sums_cost_facets(chain, issuer, trust_store):
    for cents in (1.0, 2.5, None):
        exchange = LLMExchange(model="m", prompt_context=f"p{cents}", response="r",
                               cost_estimate_cents=cents)
        capture_llm_exchange(exchange, mode=IngestMode.AGENTIC, oversight=OversightLevel.APPROVE,
                            chain=chain, signer=issuer)
    assert recorded_spend_cents(chain, trust_store=trust_store) == 3.5
