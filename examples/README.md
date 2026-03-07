# Examples

Runnable examples for common navi-sanitize use cases.

| Example | Persona | What it shows |
|---------|---------|--------------|
| [llm_pipeline.py](llm_pipeline.py) | LLM / AI builders | Sanitize user input before prompt templates — strips tag smuggling, zero-width keyword evasion, and homoglyphs |
| [fastapi_pydantic.py](fastapi_pydantic.py) | Web developers | Pydantic `AfterValidator` and FastAPI `Depends` patterns for edge sanitization |
| [log_sanitizer.py](log_sanitizer.py) | Security / SOC analysts | `walk()` on parsed log data to expose hidden IOCs |

## Running

```bash
# Only navi-sanitize is required; fastapi and pydantic are optional
pip install navi-sanitize

python examples/llm_pipeline.py
python examples/fastapi_pydantic.py
python examples/log_sanitizer.py
```

The FastAPI/Pydantic example runs standalone but also shows the integration patterns. Install `fastapi` and `pydantic` to see the full demo.
