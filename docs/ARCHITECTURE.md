# Архитектура localzet-jose

## Принцип разделения уровней

Библиотека намеренно разделяет четыре разных операции:

```text
parse -> cryptographic operation -> claims decode -> application validation
```

JWS не знает о JWT Claims. JWT не реализует собственную подпись. JWE не
использует JWS policy. JWK является представлением ключевого материала, а не
автоматическим выборщиком алгоритма.

## Недоверенные идентификаторы алгоритмов

`alg`, `enc`, `kid`, `jku` и остальные значения входящего объекта являются
недоверенными данными. Полученное из токена `alg` не должно единолично выбирать
crypto backend. Caller задаёт policy, после чего библиотека дополнительно
проверяет совпадение алгоритма с конкретным signer/verifier/key provider.

## Расширяемые registries

IANA registries являются живыми. Поэтому wire identifiers хранятся как строки,
а неизвестные Header Parameters и Claims сохраняются в `additional`.

`src/registry.rs` — snapshot известных имён, а не закрытая схема протокола.

## JWS

Signing Input строится из исходного Protected Header segment и payload в точном
wire representation. При verification заголовок не сериализуется повторно.

Поддерживаются:

- Compact Serialization;
- attached/detached payload;
- RFC 7797 `b64=false`;
- модели Flattened/General JSON Serialization;
- отдельные crypto providers.

## JWE

Для Compact Serialization Protected Header используется как AAD. `alg` отвечает
за управление CEK, `enc` — за authenticated content encryption.

Decrypt API требует явной `JweDecryptionPolicy` для обоих идентификаторов.

## JWT

Типизированы только семь registered claims самого RFC 7519. Claims из других
спецификаций не притворяются частью базового JWT и сохраняются как JSON Value.
Это позволяет библиотеке переживать расширение IANA registry без breaking API.
