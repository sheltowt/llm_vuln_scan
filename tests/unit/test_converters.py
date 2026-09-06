from llm_vuln_scan.converters.base import ConverterChain
from llm_vuln_scan.converters.encodings import Base64Converter, Rot13Converter


def test_base64_roundtrip_via_untransform():
    c = Base64Converter()
    encoded = c.transform("INJECTION_CONFIRMED here")
    # a model echoing the encoded blob should still be decodable for scoring
    decoded = c.untransform(f"the answer is {encoded}")
    assert "INJECTION_CONFIRMED" in decoded


def test_rot13_is_self_inverse():
    c = Rot13Converter()
    assert c.transform(c.transform("hello world")) == "hello world"


def test_chain_applies_in_order_and_reverses():
    chain = ConverterChain.build(["base64"])
    out = chain.transform("secret payload text")
    assert "secret" not in out
    assert "secret payload text" in chain.untransform(out)


def test_span_markers_convert_only_marked_text():
    from llm_vuln_scan.converters.encodings import LeetspeakConverter

    c = LeetspeakConverter()
    assert c.apply("keep ⟪leet⟫ plain") == "keep 1337 plain"
