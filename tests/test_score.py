from pipeline.models import Item
from pipeline.score import score_item


def _item(**kw):
    base = dict(
        id="x",
        source="PortSwigger Research",
        source_type="research",
        title="t",
        url="https://e.com",
        published="2000-01-01T00:00:00Z",  # old -> recency contributes ~0
        summary="s",
    )
    base.update(kw)
    return Item(**base)


def test_score_combines_terms_and_explains(config, watchlist):
    it = _item(
        title="Confluence RCE CVE-2024-1234",
        summary="prompt injection in the plugin",
        kev=True,
        epss=0.5,
    )
    score, reasons, hits = score_item(it, config, watchlist, has_poc=True)

    # 15 source + 40 kev + 15 epss(0.5*30) + 15 watchlist + 10 poc = 95, clamped <=100.
    assert score == 95.0
    assert "confluence" in hits and "prompt injection" in hits
    joined = " ".join(reasons)
    assert "in CISA KEV (+40)" in joined
    assert "has PoC (+10)" in joined
    assert any(r.startswith("source:") for r in reasons)


def test_score_clamps_to_max(config, watchlist):
    it = _item(title="log4j openssl confluence", kev=True, epss=1.0)
    score, _, _ = score_item(it, config, watchlist, has_poc=True)
    assert score == 100.0


def test_low_signal_item_scores_low(config, watchlist):
    it = _item(source="Simon Willison", title="a blog post", summary="nothing here")
    score, reasons, hits = score_item(it, config, watchlist)
    assert hits == []
    assert score == 6.0  # just the source weight; old date => no recency
