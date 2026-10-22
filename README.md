# landlock-smoke

Bindings mínimos de [Landlock](https://docs.kernel.org/userspace-api/landlock.html) escritos
directo contra las syscalls (`landlock_create_ruleset`, `landlock_add_rule`,
`landlock_restrict_self`; sólo depende de `libc`), un wrapper `exec` que encierra un comando y
una matriz de auto-prueba que demuestra en el kernel real qué se permite y qué se deniega.

*English below.*

## Español

### Uso

```sh
landlock-smoke abi
# abi=6 fs=0xffff net=0x3 scope=0x3

landlock-smoke selftest [--require-abi N]

landlock-smoke exec --ro /usr --ro /etc --ro /lib --rw ./out --connect 443 -- curl ...
```

`exec` maneja todos los derechos de filesystem que el kernel conoce: lo que no otorgan
`--ro`/`--rw` queda denegado. `--bind`/`--connect`/`--no-net` activan filtrado TCP (ABI 4+),
`--scope-signal`/`--scope-unix` el aislamiento IPC (ABI 6). Por defecto es *best effort*: si
el kernel no soporta algo, lo avisa por stderr y aplica el resto; `--strict` falla en su lugar.

### Qué demuestra la auto-prueba

Cada escenario restringe un hilo nuevo (Landlock es por hilo y hereditario), prueba
operaciones permitidas y denegadas con el errno exacto, y después el hilo llamador verifica
que la restricción **no** se le filtró.

| escenario | ABI | comprobación |
|---|---|---|
| fs-read-only-tree | 1 | `ro/` se lee y lista; escribir/crear da EACCES; `secret/` da EACCES |
| fs-read-write-subtree | 1 | crear, mkdir, rmdir, unlink sólo bajo `rw/` |
| fs-single-file-rule | 1 | regla sobre un archivo: sólo ese archivo; derechos de directorio se enmascaran (si no, EINVAL) |
| fs-refer | 2 | `rename` entre directorios sin REFER da **EXDEV**, no EACCES |
| fs-truncate | 3 | `O_TRUNC` y `ftruncate` requieren TRUNCATE; escribir sin truncar sí funciona |
| best-effort-abi2 | 3 | política armada para ABI 2: TRUNCATE se descarta y se reporta, el resto se aplica |
| net-bind-tcp | 4 | `bind` sólo al puerto permitido |
| net-connect-tcp | 4 | `connect` sólo al puerto permitido |
| scope-signal | 6 | `kill(pid, 0)` a un proceso fuera del dominio da EPERM |
| scope-abstract-unix | 6 | conectar a un socket abstracto fuera del dominio da EPERM |

Resultado medido en un kernel 6.12 (ABI 6): 10/10 PASS, ~8 ms la matriz completa.

### Tests

- 6 unitarios: layout de structs contra la uapi, máscaras por ABI, best-effort vs strict.
- 11 de kernel (`tests/kernel.rs`): un test por escenario + uno que exige que cada escenario
  tenga su test. Con `LANDLOCK_SMOKE_REQUIRE_ABI=N` un escenario salteado de ABI ≤ N falla.
- 8 end-to-end (`tests/cli.rs`): `exec` real de `cat`/`sh`/`bash`: lectura fuera del árbol
  denegada, escritura sólo bajo `--rw`, la restricción sobrevive a nietos, filtro TCP con
  `/dev/tcp`, códigos de salida 2/127.

CI corre `cargo test` y `selftest` en runners x86-64 y AArch64 exigiendo ABI ≥ 4, más
fmt/clippy y build con MSRV 1.75. Los escenarios de ABI 6 se saltean donde el kernel del
runner sea más viejo.

### Límites

- Sólo Linux; sin soporte para ABI 7 (flags de logging de auditoría).
- No es un sandbox completo: Landlock no filtra syscalls (para eso, seccomp), ni UDP, ni
  `/proc` ya abiertos antes de restringir. Los fds abiertos antes de `restrict_self` conservan
  su acceso.

## English

Minimal Landlock bindings over raw syscalls (only `libc`), an `exec` wrapper that confines
a command, and a self-test matrix that shows on the running kernel what is allowed and
denied, asserting the exact errno.

- `abi` prints the kernel ABI and the rights masks it can enforce.
- `selftest` runs ten scenarios (filesystem read/write/single-file/REFER/TRUNCATE, a
  best-effort policy built for an older ABI, TCP bind/connect, signal and abstract-unix
  scoping). Each one restricts a fresh thread; the caller then checks the restriction did not
  leak to it. Measured on a 6.12 kernel (ABI 6): 10/10 pass in ~8 ms.
- `exec` handles every filesystem right the kernel knows; only `--ro`/`--rw` paths are
  reachable. Best effort by default (warns on stderr), `--strict` refuses to weaken the policy.

Tests: 6 unit, 11 kernel (one per scenario, `LANDLOCK_SMOKE_REQUIRE_ABI` turns skips into
failures), 8 end-to-end CLI tests. CI runs them on x86-64 and AArch64 runners requiring
ABI ≥ 4, plus fmt/clippy and an MSRV 1.75 build.

Limits: Linux only; ABI 7 audit flags not covered. Landlock is not a syscall filter (pair it
with seccomp), does not cover UDP, and fds opened before `restrict_self` keep their access.

## License

Apache-2.0.
