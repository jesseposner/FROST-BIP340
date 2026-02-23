# Running Tests

```bash
uv run python -m pytest                       # full suite
uv run python -m pytest tests/test_sign.py    # specific file
uv run python -m pytest -k test_keygen        # specific test
```

### Test Coverage

```bash
uv run python -m pytest --cov=frost
```
