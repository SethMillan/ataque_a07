# Ataque A07 — Login vulnerable vs mitigado

Proyecto educativo que demuestra **A07: Identification and Authentication Failures** (OWASP Top 10) mediante un login sin protecciones y su versión endurecida.

- `vulnerable/` — login sin defensas contra fuerza bruta
- `mitigated/` — login con rate-limit, bloqueo de cuenta, bcrypt y CAPTCHA

Credenciales en ambas versiones: `admin/admin123` y `user/user123`.

---

## Guía de pruebas: vulnerable vs mitigada

### 1. Probar la versión VULNERABLE

#### Arrancar el servidor
```bash
cd vulnerable
node server.js
```
Verás `Server is running on port 3000`. Abre **http://localhost:3000**

#### Prueba A — Login correcto
1. Usuario: `admin` · Contraseña: `admin123` → toast verde "Login exitoso"
2. Click en **"Ir al Dashboard"** → ves `{"message":"Bienvenido admin"}`

#### Prueba B — Demostrar la vulnerabilidad (sin límite de intentos)
1. Vuelve a `http://localhost:3000`
2. Escribe `admin` / `cualquier_cosa` y presiona Enter **repetidamente** (10, 20, 50 veces…)
3. **Observa:** el contador rojo sube infinitamente, el servidor **nunca bloquea ni ralentiza**

#### Prueba C — Fuerza bruta automatizada con `curl` (la prueba real)
En otra terminal, simula un atacante probando 10 contraseñas en segundos:
```bash
for pass in admin123 password 123456 qwerty letmein admin admin1 password1 root toor; do
  echo -n "$pass → "
  curl -s -X POST http://localhost:3000/login \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"admin\",\"password\":\"$pass\"}"
  echo
done
```
**Resultado esperado:** el servidor responde a TODAS las peticiones. La contraseña `admin123` devuelve `{"success":true,...}`. **No hay ningún 429, ningún bloqueo, ninguna defensa.**

#### Detener
`Ctrl+C` en la terminal del servidor.

---

### 2. Probar la versión MITIGADA

#### Arrancar el servidor
```bash
cd mitigated
npm install   # solo la primera vez
node server.js
```
`Mitigated server running on port 3000`. Abre **http://localhost:3000** (recarga si tenías el vulnerable abierto).

> **Tip:** abre una pestaña en **modo incógnito** para tener una cookie de sesión limpia.

#### Prueba A — Login correcto
1. `admin` / `admin123` → toast verde
2. Click en **"Ir al Dashboard"** → `{"message":"Bienvenido admin"}`

#### Prueba B — Disparar el CAPTCHA (3 intentos fallidos)
1. Recarga la página
2. Escribe `admin` / `mal1` → Enter → toast rojo + caja amarilla "**4** intentos restantes"
3. `admin` / `mal2` → "3 intentos restantes"
4. `admin` / `mal3` → **aparece la caja azul con el CAPTCHA** (`X + Y = ?`)
5. Intenta loguear sin resolverlo → server responde "Resuelve el CAPTCHA"
6. Resuelve el CAPTCHA + contraseña correcta `admin123` → login exitoso

#### Prueba C — Disparar el BLOQUEO de cuenta (5 fallos)
1. Recarga (o usa el usuario `user`)
2. Falla 5 veces seguidas con `user` / `xxx` (cuando aparezca el CAPTCHA, resuélvelo bien pero password mal)
3. **Al 5º fallo:** caja roja "Cuenta bloqueada — 900 segundos restantes", **formulario deshabilitado**
4. Aunque resuelvas el CAPTCHA, no podrás intentar durante 15 minutos
5. En la terminal del server verás: `[SECURITY] Cuenta "user" bloqueada hasta ...`

#### Prueba D — Hash bcrypt (verificar que no hay passwords en claro)
```bash
grep -E "admin123|user123" mitigated/server.js
```
Solo aparecen como argumento de `bcrypt.hashSync(...)`, **nunca almacenados en claro**.

#### Prueba E — Rate-limit por IP (defensa contra fuerza bruta automatizada)
Mismo ataque que en la vulnerable, ahora contra la mitigada:
```bash
for i in $(seq 1 15); do
  echo -n "intento $i → "
  curl -s -o /dev/null -w "HTTP %{http_code}\n" -X POST http://localhost:3000/login \
    -H "Content-Type: application/json" \
    -d '{"username":"ghost","password":"x"}'
done
```
**Resultado esperado:**
- Los primeros ~10 → `HTTP 401` (credenciales mal)
- A partir del 11 → `HTTP 429` (**rate-limit por IP activado**)
- En el navegador verás "Demasiados intentos desde tu IP"

#### Prueba F — Cookie endurecida
En el navegador (DevTools → Application → Cookies → `localhost`):
- `HttpOnly` (no accesible desde JS → mitiga XSS robo de sesión)
- `SameSite` = `Lax` (mitiga CSRF)
- `Expires`: ~30 min (vs. ~31 años en la vulnerable)

#### Detener
`Ctrl+C` en la terminal del servidor.

---

## Tabla comparativa de lo que deberías observar

| Acción | Vulnerable | Mitigada |
|---|---|---|
| 50 intentos rápidos en el navegador | Todos pasan, contador infinito | Bloqueo a los 5, CAPTCHA a los 3 |
| 15 requests `curl` en bucle | Todos 401 | A partir del ~11º: **429 (rate-limit IP)** |
| Cookie de sesión | maxAge ~31 años | maxAge 30 min, HttpOnly, SameSite |
| Passwords | En claro en `server.js` | Hash bcrypt |
| Logs del servidor | Silencioso | `[SECURITY] Login fallido…` / `bloqueada` |

> **Importante:** si bloqueas una cuenta y quieres reiniciar para volver a probar, basta con **reiniciar `node server.js`** (el estado está en memoria).
