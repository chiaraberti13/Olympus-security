# API Client Examples

## cURL

```bash
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -H "x-api-key: <API_KEY>" \
  -H "Authorization: Bearer <JWT>" \
  -d '{"target": "https://example.com", "scan_type": "full", "priority": 5}'
```

## Python (requests)

```python
import requests

payload = {
    "target": "https://example.com",
    "scan_type": "full",
    "priority": 5,
}

response = requests.post(
    "http://localhost:8000/api/v1/scans",
    json=payload,
    headers={
        "x-api-key": "<API_KEY>",
        "Authorization": "Bearer <JWT>",
    },
    timeout=30,
)
response.raise_for_status()
print(response.json())
```

## JavaScript (fetch)

```javascript
const payload = {
  target: "https://example.com",
  scan_type: "full",
  priority: 5,
};

const response = await fetch("http://localhost:8000/api/v1/scans", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "x-api-key": "<API_KEY>",
    "Authorization": "Bearer <JWT>",
  },
  body: JSON.stringify(payload),
});

if (!response.ok) {
  throw new Error(`HTTP ${response.status}`);
}

console.log(await response.json());
```
