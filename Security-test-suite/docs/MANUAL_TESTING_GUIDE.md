# Manuální průvodce — Security testování Juice Shop

## Příprava — spuštění aplikace

Otevři **dva terminály** ve VS Code (`Ctrl+`` ` ``).

**Terminál 1 — Juice Shop:**
```powershell
cd C:\Users\steve\Desktop\Projects\juice-shop_19.2.1
node build/app.js
```
Počkej na: `Server listening on port 3000`

**Terminál 2 — testy:**
```powershell
cd C:\Users\steve\Desktop\Projects\Security-test-suite
```

Otevři prohlížeč: **http://localhost:3000**

---

## ČÁST 1 — Prozkoumej appku ručně (10 minut)

### Krok 1 — Registrace
1. Klikni vpravo nahoře na ikonu osoby → **Account → Login**
2. Klikni **"Not yet a customer?"**
3. Zadej:
   - Email: `test@fake.local`
   - Password: `Test1234!`
   - Repeat: `Test1234!`
   - Security question: vyber cokoliv, odpověz cokoliv
4. Klikni **Register**

### Krok 2 — Přihlášení
1. Zadej `test@fake.local` a `Test1234!`
2. Klikni **Login**
3. Úspěch = vidíš e-shop s produkty

### Krok 3 — Prozkoumej funkce
- Zkus **vyhledat** produkt (ikona lupy nahoře) → napiš `apple`
- Klikni na produkt → přidej do košíku
- Zkus napsat **recenzi** na produkt
- Koukni do **F12 → Network** → vidíš API volání (Request/Response)

---

## ČÁST 2 — Manuální security testy

### TEST 1 — SQL Injection (login bypass)

**Co zkoušíme:** Obejít přihlášení bez hesla pomocí SQL kódu

1. Jdi na **login stránku** (`http://localhost:3000/#/login`)
2. Do pole Email zadej:
   ```
   ' OR 1=1--
   ```
3. Do pole Password zadej cokoliv: `xxx`
4. Klikni Login

**Výsledek Juice Shop:**
- Přihlásí tě jako admin → **ZRANITELNOST NALEZENA**
- Vrátí chybu → aplikace je chráněná

---

### TEST 2 — XSS (Cross-site scripting)

**Co zkoušíme:** Vložit JavaScript do search baru

1. Klikni na ikonu **lupy** (search)
2. Zadej:
   ```
   <script>alert('XSS')</script>
   ```
3. Stiskni Enter

**Výsledek Juice Shop:**
- Zobrazí se popup `alert` → **ZRANITELNOST NALEZENA**
- Zobrazí se jako text `<script>...` → aplikace je chráněná

---

### TEST 3 — IDOR (přístup k cizím datům)

**Co zkoušíme:** Přečíst košík jiného uživatele změnou čísla v URL

1. Přihlaš se (pokud nejsi)
2. Do adresního řádku zadej přímo:
   ```
   http://localhost:3000/rest/basket/1
   ```
3. Zkus různá čísla: `/1`, `/2`, `/3`

**Výsledek Juice Shop:**
- Vrátí data košíku → **ZRANITELNOST NALEZENA** (IDOR)
- Vrátí 401/403 → aplikace je chráněná

---

### TEST 4 — Slabé heslo

**Co zkoušíme:** Registrovat se s heslem "123"

1. Jdi na **registraci** (`http://localhost:3000/#/register`)
2. Email: `slabe@fake.local`
3. Password: `123`
4. Zkus odeslat

**Výsledek Juice Shop:**
- Registrace proběhne → **ZRANITELNOST NALEZENA**
- Zobrazí chybu "password too weak" → aplikace je chráněná

---

### TEST 5 — Security headers

**Co zkoušíme:** Jsou nastavené bezpečnostní HTTP hlavičky?

1. Otevři `http://localhost:3000`
2. F12 → záložka **Network**
3. Klikni na první request (řádek `localhost`)
4. Klikni na záložku **Response Headers**
5. Hledej tyto hlavičky:

| Hlavička | Má být přítomna | Juice Shop |
|----------|----------------|-----------|
| `X-Frame-Options` | ANO | ✅ přítomna |
| `X-Content-Type-Options` | ANO | ✅ přítomna |
| `Content-Security-Policy` | ANO | ❌ chybí → ZRANITELNOST |
| `Strict-Transport-Security` | ANO | ❌ chybí → ZRANITELNOST |

---

### TEST 6 — Admin panel bez oprávnění

**Co zkoušíme:** Dostat se na admin stránku jako normální uživatel

1. Přihlaš se jako `test@fake.local`
2. Do URL zadej:
   ```
   http://localhost:3000/#/administration
   ```

**Výsledek Juice Shop:**
- Zobrazí admin panel → **ZRANITELNOST NALEZENA**
- Přesměruje na login → aplikace je chráněná

---

### TEST 7 — Default credentials

**Co zkoušíme:** Fungují výchozí hesla?

1. Jdi na login
2. Zadej:
   - Email: `admin@juice-sh.op`
   - Password: `admin123`
3. Klikni Login

**Výsledek Juice Shop:**
- Přihlásí tě jako admin → **ZRANITELNOST NALEZENA**
- Vrátí chybu → aplikace změnila default heslo

---

## ČÁST 3 — Automatické testy

Po manuálním průzkumu spusť automatizované testy:

```powershell
# Všechny API testy
python -m pytest tests/api/ -v

# Jen to co jsi testoval ručně
python -m pytest -m sqli -v          # TEST 1 - SQL Injection
python -m pytest -m xss -v           # TEST 2 - XSS
python -m pytest -m idor -v          # TEST 3 - IDOR
python -m pytest -m auth -v          # TEST 4, 7 - Hesla, credentials
python -m pytest -m headers -v       # TEST 5 - Headers

# S HTML reportem
python -m pytest tests/api/ --html=reports/report.html --self-contained-html
```

Otevři `reports/report.html` v prohlížeči pro přehledné výsledky.

---

## Jak číst výsledky

```
PASSED = aplikace se brání = dobře
FAILED = nalezená zranitelnost = test splnil účel
```

**Příklad z Juice Shopu:**
```
FAILED test_registration_rejects_weak_password['123']
→ Juice Shop přijal heslo "123" = reálná zranitelnost

PASSED test_jwt_none_algorithm
→ Juice Shop odmítl padělaný JWT = ochrana funguje
```

---

## Co říct na pohovoru

> *"Nejdřív prozkoumám appku ručně jako uživatel — projdu všechny funkce,
> kouknu do Network tabu, zmapuju kde se zadávají data.
> Pak systematicky testuji podle OWASP Top 10 —
> SQL injection do formulářů, IDOR přes změnu ID v URL,
> security headers v HTTP odpovědích.
> Co najdu ručně, automatizuji do pytest testů.
> FAIL u security testu znamená nalezenou zranitelnost, ne chybu v testu."*
