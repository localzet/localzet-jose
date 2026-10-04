# Security

Этот репозиторий создаётся как учебная/reference реализация JOSE.

До отдельного security audit его не следует считать заменой зрелой
production-библиотеки для финансовых, медицинских или иных high-risk систем.

## Основные правила проекта

- `alg` из токена не выбирает алгоритм без allow-list caller-а.
- `none` запрещён по умолчанию.
- HMAC требует минимальную длину ключа согласно размеру hash output.
- RSA signing keys должны быть не меньше 2048 бит.
- JWS verification использует оригинальные encoded segments.
- `crit` не игнорируется.
- `b64=false` обрабатывается отдельно.
- Cryptographic verification и JWT claims validation разделены.
- JWE AES-GCM использует Protected Header как AAD.
- `RSA1_5` известен registry, но crypto operation намеренно отключена в baseline.
- JWE decrypt требует allow-list для `alg` и `enc`.
