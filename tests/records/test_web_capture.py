from __future__ import annotations

from agent_gate.records import chain_receipt
from agent_gate.records.llm_capture import IngestMode, OversightLevel, VerbosityLevel
from agent_gate.records.web_capture import WebSearchExchange, WebSearchResult, capture_web_exchange


def test_metadata_verbosity_hides_the_query(chain, issuer):
    exchange = WebSearchExchange(query="divorce lawyer near me", engine="test-engine",
                                 results=[WebSearchResult(url="https://x", snippet="s")])
    capture_web_exchange(exchange, mode=IngestMode.AGENTIC, oversight=OversightLevel.AUTONOMOUS,
                         chain=chain, signer=issuer)
    payload = chain_receipt.payloads(chain)[-1]
    assert "query" not in payload["facets"]
    assert "divorce" not in str(payload)


def test_preview_verbosity_reveals_query_and_snippet(chain, issuer):
    exchange = WebSearchExchange(query="divorce lawyer near me", engine="test-engine",
                                 results=[WebSearchResult(url="https://x", snippet="a snippet", rank=1)])
    result = capture_web_exchange(exchange, mode=IngestMode.AGENTIC, oversight=OversightLevel.NOTIFY,
                                  chain=chain, signer=issuer)
    assert result.verbosity == VerbosityLevel.PREVIEW
    payload = chain_receipt.payloads(chain)[-1]
    assert payload["facets"]["query"] == "divorce lawyer near me"
    assert payload["results"][0]["snippet"] == "a snippet"
