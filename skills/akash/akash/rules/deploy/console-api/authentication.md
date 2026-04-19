# Console API Authentication

Authentication methods for the Akash Console API.

## Authentication Methods

| Method | Use Case | Security |
|--------|----------|----------|
| **API Key** | Server-to-server | High |
| **JWT Token** | User sessions | High |
| **Anonymous** | Public endpoints only | N/A |

## API Key Authentication

### Obtaining an API Key

1. Visit [Akash Console](https://console.akash.network)
2. Connect your wallet
3. Navigate to Settings > API Keys
4. Click "Generate New Key"
5. Copy and securely store the key

### Using API Keys

Include the key in the `Authorization` header:

```bash
curl https://console-api.akash.network/v1/deployment \
  -H "Authorization: Bearer <your-api-key>"
```

### API Key Best Practices

- **Never commit** API keys to version control
- **Use environment variables** for key storage
- **Rotate keys** periodically
- **Set key restrictions** when possible
- **Use separate keys** for development and production

### Environment Variable Usage

```bash
# Set in environment
export AKASH_API_KEY="your-api-key-here"

# Use in curl
curl https://console-api.akash.network/v1/deployment \
  -H "Authorization: Bearer $AKASH_API_KEY"
```

### Code Examples

**JavaScript/TypeScript:**
```typescript
const API_KEY = process.env.AKASH_API_KEY;

const response = await fetch('https://console-api.akash.network/v1/deployment', {
  headers: {
    'Authorization': `Bearer ${API_KEY}`,
    'Content-Type': 'application/json'
  }
});
```

**Python:**
```python
import os
import requests

API_KEY = os.environ.get('AKASH_API_KEY')

response = requests.get(
    'https://console-api.akash.network/v1/deployment',
    headers={'Authorization': f'Bearer {API_KEY}'}
)
```

**Go:**
```go
apiKey := os.Getenv("AKASH_API_KEY")

req, _ := http.NewRequest("GET", "https://console-api.akash.network/v1/deployment", nil)
req.Header.Set("Authorization", "Bearer "+apiKey)

client := &http.Client{}
resp, _ := client.Do(req)
```

## JWT Authentication

For web applications and user-authenticated requests.

### Obtaining JWT Token

JWT tokens are obtained through the OAuth flow:

```
1. User initiates login at Console
2. User authenticates via wallet
3. Console returns JWT token
4. Use token for API requests
```

### Using JWT Tokens

```bash
curl https://console-api.akash.network/v1/deployment \
  -H "Authorization: Bearer <jwt-token>"
```

### Token Structure

```javascript
// JWT payload structure
{
  "sub": "akash1...",       // Wallet address
  "iat": 1704067200,        // Issued at
  "exp": 1704153600,        // Expiration
  "iss": "console.akash.network"
}
```

### Token Refresh

JWT tokens expire. Implement refresh logic:

```typescript
class AkashApiClient {
  private token: string;
  private tokenExpiry: number;

  async getToken(): Promise<string> {
    if (Date.now() > this.tokenExpiry) {
      await this.refreshToken();
    }
    return this.token;
  }

  async refreshToken(): Promise<void> {
    // Implement refresh logic
    const response = await fetch('https://console-api.akash.network/v1/auth/refresh', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${this.token}` }
    });
    const { token, expiresIn } = await response.json();
    this.token = token;
    this.tokenExpiry = Date.now() + (expiresIn * 1000);
  }
}
```

## Public Endpoints

Some endpoints don't require authentication:

| Endpoint | Description |
|----------|-------------|
| `GET /providers` | List public providers |
| `GET /status` | API health status |
| `POST /sdl/validate` | Validate SDL (limited) |

```bash
# No authentication required
curl https://console-api.akash.network/v1/providers
```

## Error Responses

### 401 Unauthorized

```json
{
  "success": false,
  "error": {
    "code": "UNAUTHORIZED",
    "message": "Invalid or missing authentication token"
  }
}
```

**Causes:**
- Missing Authorization header
- Invalid API key
- Expired JWT token

### 403 Forbidden

```json
{
  "success": false,
  "error": {
    "code": "FORBIDDEN",
    "message": "API key does not have permission for this operation"
  }
}
```

**Causes:**
- API key restrictions
- Insufficient permissions

## Security Considerations

### Key Storage

**DO:**
- Use environment variables
- Use secrets management (Vault, AWS Secrets Manager)
- Encrypt keys at rest

**DON'T:**
- Hardcode in source code
- Commit to version control
- Share keys between environments
- Log keys in output

### Request Security

Always use HTTPS:

```bash
# CORRECT
https://console-api.akash.network/v1/...

# WRONG - Never use HTTP
http://console-api.akash.network/v1/...
```

### Key Rotation

Regularly rotate API keys:

1. Generate new key
2. Update applications to use new key
3. Verify new key works
4. Revoke old key

### Monitoring

Monitor API key usage for anomalies:

- Unusual request patterns
- Requests from unexpected IPs
- Failed authentication attempts

## CI/CD Integration

### GitHub Actions

```yaml
env:
  AKASH_API_KEY: ${{ secrets.AKASH_API_KEY }}

steps:
  - name: Deploy to Akash
    run: |
      curl -X POST https://console-api.akash.network/v1/deployment \
        -H "Authorization: Bearer $AKASH_API_KEY" \
        -d '{"sdl": "..."}'
```

### GitLab CI

```yaml
variables:
  AKASH_API_KEY: $AKASH_API_KEY  # From CI/CD settings

deploy:
  script:
    - |
      curl -X POST https://console-api.akash.network/v1/deployment \
        -H "Authorization: Bearer $AKASH_API_KEY" \
        -d '{"sdl": "..."}'
```

### Docker

```dockerfile
# Use build args for API keys (not recommended for production)
ARG AKASH_API_KEY
ENV AKASH_API_KEY=$AKASH_API_KEY

# Better: Mount secrets at runtime
# docker run -e AKASH_API_KEY=$AKASH_API_KEY myimage
```

## Troubleshooting

### Invalid Token

```bash
# Check token format
echo $AKASH_API_KEY | base64 -d  # Should decode if base64
```

### Rate Limited

```json
{
  "error": {
    "code": "RATE_LIMITED",
    "message": "Too many requests",
    "retryAfter": 60
  }
}
```

Wait and retry with exponential backoff:

```typescript
async function fetchWithRetry(url: string, options: RequestInit) {
  for (let i = 0; i < 3; i++) {
    const response = await fetch(url, options);
    if (response.status === 429) {
      const retryAfter = parseInt(response.headers.get('Retry-After') || '60');
      await new Promise(r => setTimeout(r, retryAfter * 1000));
      continue;
    }
    return response;
  }
  throw new Error('Max retries exceeded');
}
```
