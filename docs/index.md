---
hide:
  - navigation
  - toc
---

<div class="hero-glow" markdown>

# navi-sanitize

**Deterministic input sanitization for untrusted text.**

Homoglyphs, invisible characters, null bytes, NFKC normalization, template injection. Zero dependencies. Python 3.12+.

[Get Started](getting-started/quickstart.md){ .md-button .md-button--primary }
[API Reference](#){ .md-button }

</div>

---

## What it does

Strip dangerous characters, normalize Unicode, and neutralize injection vectors --- deterministically, with no ML and no network calls.

```python
from navi_sanitize import sanitize

clean = sanitize(untrusted_input)
```

## What's next

- **[Quickstart](getting-started/quickstart.md)** --- get started in 60 seconds
