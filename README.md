# Identity Framework For Microservices

# Architettura Identity Centralizzata con JWT e JWKS

## Obiettivo

Progettare un'architettura centralizzata per la gestione dell'identità utente (inclusi utenti anonimi) utilizzando JWT firmati con chiavi asimmetriche e un endpoint JWKS pubblico per la validazione distribuita dei token.

## Componenti Principali

### 1. API Identity (in .NET)
- Responsabile della generazione e firma dei JWT (anonimi e autenticati).
- Espone un endpoint JWKS pubblico per la chiave pubblica.
- Firma i token con chiave privata `RS256`.
- URL pubblica: `https://identitysso.ws`

### 2. Resource APIs
- Non gestiscono autenticazione direttamente.
- Validano i JWT utilizzando la chiave pubblica recuperata dal JWKS endpoint.

## Architettura Tecnica

```plaintext
                +------------------+
                | Client / Browser |
                +--------+---------+
                         |
                         v
           +-------------+-------------+
           |    Identity API (.NET)    |
           | https://identitysso.ws    |
           +-------------+-------------+
                         |
           +-------------+-------------+
           |   JWKS Endpoint:           |
           | https://identitysso.ws/   |
           | .well-known/jwks.json     |
           +-------------+-------------+
                         |
           +-------------+-------------+
           |      Resource APIs        |
           |  (verifica firma JWT)     |
           +---------------------------+
```

## Endpoint JWKS - Esempio di Risposta

```json
{
  "keys": [
    {
      "kid": "my-key-id",
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "n": "<base64url-modulus>",
      "e": "AQAB"
    }
  ]
}
```

## Firma del JWT (Identity API)

```csharp
var rsa = RSA.Create(2048);
var key = new RsaSecurityKey(rsa)
{
    KeyId = "my-key-id"
};

var credentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256);

var tokenDescriptor = new SecurityTokenDescriptor
{
    Issuer = "https://identitysso.ws",
    Audience = "chatbot-api",
    Expires = DateTime.UtcNow.AddMinutes(30),
    SigningCredentials = credentials,
    Subject = new ClaimsIdentity(new[]
    {
        new Claim("sub", "anon-guest"),
        new Claim("role", "anonymous"),
        new Claim("scope", "chat:read chat:write")
    })
};

var handler = new JwtSecurityTokenHandler();
var token = handler.CreateToken(tokenDescriptor);
var jwt = handler.WriteToken(token);
```

## JWKS Endpoint (API Controller in .NET)

```csharp
[ApiController]
[Route(".well-known/jwks.json")]
public class JwksController : ControllerBase
{
    private readonly RsaSecurityKey _key;

    public JwksController(IKeyProvider keyProvider)
    {
        _key = keyProvider.GetPublicKey();
    }

    [HttpGet]
    public IActionResult GetJwks()
    {
        var parameters = _key.Rsa.ExportParameters(false);

        var jwk = new
        {
            keys = new[]
            {
                new
                {
                    kid = _key.KeyId,
                    kty = "RSA",
                    use = "sig",
                    alg = "RS256",
                    n = Base64UrlEncoder.Encode(parameters.Modulus),
                    e = Base64UrlEncoder.Encode(parameters.Exponent)
                }
            }
        };

        return Ok(jwk);
    }
}
```

## Validazione del Token nelle Resource API

```csharp
var rsa = RSA.Create();
// Simulazione caricamento chiave da https://identitysso.ws/.well-known/jwks.json
rsa.ImportParameters(new RSAParameters
{
    Modulus = Base64UrlEncoder.DecodeBytes("<modulus>"),
    Exponent = Base64UrlEncoder.DecodeBytes("AQAB")
});

var validationParams = new TokenValidationParameters
{
    ValidateIssuer = true,
    ValidIssuer = "https://identitysso.ws",
    ValidateAudience = true,
    ValidAudience = "chatbot-api",
    ValidateLifetime = true,
    ValidateIssuerSigningKey = true,
    IssuerSigningKey = new RsaSecurityKey(rsa),
    ClockSkew = TimeSpan.FromSeconds(30)
};

var handler = new JwtSecurityTokenHandler();
handler.ValidateToken(jwt, validationParams, out var validatedToken);
```

## Meccanismo Automatico di Scoperta e Validazione via JWKS

Quando si utilizza `AddJwtBearer` in ASP.NET Core per configurare l'autenticazione con token JWT, il middleware è in grado di eseguire automaticamente la scoperta e il download della chiave pubblica necessaria per la validazione. Questo avviene nel seguente modo:

### 1. Configurazione semplice dell'API Resource:

```csharp
services.AddAuthentication("Bearer")
    .AddJwtBearer("Bearer", options =>
    {
        options.Authority = "https://identitysso.ws";
        options.Audience = "chatbot-api";
        options.RequireHttpsMetadata = true;
    });
```

### 2. Cosa succede internamente:
- Il middleware effettua una chiamata automatica a:
  ```
  https://identitysso.ws/.well-known/openid-configuration
  ```
- Questo endpoint deve restituire un JSON contenente il campo `jwks_uri`, es:

```json
{
  "issuer": "https://identitysso.ws",
  "jwks_uri": "https://identitysso.ws/.well-known/jwks.json"
}
```

- Successivamente scarica e cache-a la chiave pubblica da quell'URL per validare i JWT.

### 3. Vantaggi:
- Nessun bisogno di scrivere codice custom per scaricare e validare la chiave.
- Supporto automatico per rotazione delle chiavi grazie al campo `kid` nei JWT.

### 4. In caso di implementazione custom:
Se non si utilizza `AddJwtBearer`, si può comunque fare una chiamata HTTP manuale a `/.well-known/jwks.json`, leggere `n` ed `e`, e costruire la chiave pubblica con `RSAParameters` per validare manualmente il JWT.

## Supporto per Refresh Token

Per supportare anche i refresh token, è possibile estendere l'API Identity con:

### Interfaccia per gestire i refresh token

```csharp
public interface IRefreshTokenStore
{
    Task<string> GenerateAsync(string subjectId);
    Task<bool> ValidateAsync(string subjectId, string refreshToken);
}
```

### Implementazione In-Memory (esempio base)

```csharp
public class InMemoryRefreshTokenStore : IRefreshTokenStore
{
    private readonly ConcurrentDictionary<string, string> _tokens = new();

    public Task<string> GenerateAsync(string subjectId)
    {
        var token = Guid.NewGuid().ToString("N");
        _tokens[subjectId] = token;
        return Task.FromResult(token);
    }

    public Task<bool> ValidateAsync(string subjectId, string refreshToken)
    {
        return Task.FromResult(_tokens.TryGetValue(subjectId, out var stored) && stored == refreshToken);
    }
}
```

### Endpoint API esteso con refresh

```csharp
[ApiController]
[Route("api/token")]
public class TokenController : ControllerBase
{
    private readonly ICustomIdentityProvider _identityProvider;
    private readonly SigningCredentials _signingCredentials;
    private readonly IRefreshTokenStore _refreshTokenStore;

    public TokenController(
        ICustomIdentityProvider identityProvider,
        SigningCredentials signingCredentials,
        IRefreshTokenStore refreshTokenStore)
    {
        _identityProvider = identityProvider;
        _signingCredentials = signingCredentials;
        _refreshTokenStore = refreshTokenStore;
    }

    [HttpPost]
    public async Task<IActionResult> GenerateToken()
    {
        var user = await _identityProvider.GetAsync(HttpContext);
        if (user == null)
            return Unauthorized();

        var jwt = CreateJwt(user);
        var refreshToken = await _refreshTokenStore.GenerateAsync(user.SubjectId);

        return Ok(new TokenResponse
        {
            AccessToken = jwt,
            RefreshToken = refreshToken
        });
    }

    [HttpPost("refresh")]
    public async Task<IActionResult> RefreshToken([FromBody] TokenResponse model)
    {
        var handler = new JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(model.AccessToken);

        var sub = jwt.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Sub)?.Value;
        if (string.IsNullOrEmpty(sub))
            return Unauthorized();

        var isValid = await _refreshTokenStore.ValidateAsync(sub, model.RefreshToken);
        if (!isValid)
            return Unauthorized();

        var user = new CustomIdentityUser
        {
            SubjectId = sub,
            Role = jwt.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value ?? "anonymous",
            Scopes = jwt.Claims.FirstOrDefault(c => c.Type == "scope")?.Value?.Split(" ") ?? []
        };

        var newJwt = CreateJwt(user);
        var newRefresh = await _refreshTokenStore.GenerateAsync(user.SubjectId);

        return Ok(new TokenResponse
        {
            AccessToken = newJwt,
            RefreshToken = newRefresh
        });
    }

    private string CreateJwt(CustomIdentityUser user)
    {
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.SubjectId),
            new Claim(ClaimTypes.Role, user.Role),
            new Claim("scope", string.Join(" ", user.Scopes))
        };

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(30),
            Issuer = "https://identitysso.ws",
            Audience = "chatbot-api",
            SigningCredentials = _signingCredentials
        };

        var handler = new JwtSecurityTokenHandler();
        var token = handler.CreateToken(tokenDescriptor);
        return handler.WriteToken(token);
    }
}
```
