# JWT-inspektøren

En enkel webapp som dekoder og verifiserer JSON Web Tokens (JWT). Alt skjer i nettleseren. Tokenet sendes aldri til noen server.

## Funksjoner

- Dekoder header og payload og viser dem som formatert JSON.
- Viser tidspunktene `iat`, `nbf` og `exp` i lokal tid med tidssone (f.eks. `UTC+2`). Grønt betyr gyldig, rødt betyr ugyldig.
- Verifiserer signaturen på to måter:
  - Henter offentlig nøkkel fra utstederen (`iss`) via OpenID Connect discovery (`/.well-known/openid-configuration` → `jwks_uri`). Nøkkelen velges ut fra `kid` i tokenets header.
  - Bruker en nøkkel du limer inn: JWK, JWKS, offentlig PEM-nøkkel (`BEGIN PUBLIC KEY`) eller HMAC-hemmelighet.
- Støtter algoritmene RS256/384/512, PS256/384/512, ES256/384/512, HS256/384/512 og EdDSA. `alg: none` avvises.

## Bruk

Lim inn et token i tekstfeltet. Det dekodes med en gang. Tokenet kan også sendes inn via URL:

| Form | Eksempel |
|---|---|
| Hash (anbefalt) | `https://<host>/#eyJ...` |
| Sti | `https://<host>/eyJ...` |
| Query | `https://<host>/?token=eyJ...` |

Bruk hash-varianten for ekte tokens. Alt etter `#` sendes aldri til serveren. Tokens i sti eller query kan havne i logger hos proxyer og servere.

## Hente nøkler fra utstederen (CORS)

Nettleseren kan bare hente nøkler fra en utsteder som svarer med `Access-Control-Allow-Origin` på discovery- og JWKS-endepunktene. Uten den headeren blokkerer nettleseren svaret, og appen viser en feilmelding med lenke for manuell henting.

Dette må fikses hos utstederen. Begge endepunktene serverer offentlige data uten innlogging, så `Access-Control-Allow-Origin: *` er trygt.

Manuell løsning: åpne `jwks_uri` i en ny fane, kopier JSON-innholdet og lim det inn i nøkkelfeltet.

## Kjøre lokalt

Appen består av tre statiske filer: `index.html`, `app.js` og `styles.css`. Uten byggesteg:

```bash
npx serve -s .
```

`-s` gjør at ukjente stier serverer `index.html`, slik at `/<token>` fungerer.

## Installere i Kubernetes

Helm-chartet i [`charts/jwtinspektoren`](charts/jwtinspektoren) kjører `nginxinc/nginx-unprivileged`. De tre filene legges i et ConfigMap, så det trengs ikke et eget image. Filene i `charts/jwtinspektoren/files/` er symlenker til filene i rotmappen.

```bash
helm upgrade --install jwtinspektoren charts/jwtinspektoren \
  -n jwtinspektoren --create-namespace \
  --set ingress.enabled=true \
  --set ingress.className=nginx \
  --set 'ingress.hosts[0].host=jwt.example.no' \
  --set 'ingress.hosts[0].paths[0].path=/' \
  --set 'ingress.hosts[0].paths[0].pathType=Prefix'
```

Viktige verdier i [`values.yaml`](charts/jwtinspektoren/values.yaml):

| Verdi | Standard | Beskrivelse |
|---|---|---|
| `replicaCount` | `2` | Antall pods |
| `image.tag` | `1.27-alpine` | nginx-versjon |
| `accessLog` | `false` | Tilgangslogg i nginx. Av som standard, fordi tokens i stien ellers blir logget. |
| `ingress.enabled` | `false` | Opprett Ingress |

Containeren kjører som ikke-root med skrivebeskyttet filsystem og uten Linux-capabilities. nginx setter sikkerhetsheadere og `Cache-Control: no-cache`.

## Sikkerhet

- Content Security Policy begrenser skript og stiler til appens egne filer. Nettverkskall er bare tillatt over HTTPS.
- Dekodede verdier settes inn som ren tekst og kan ikke kjøre kode i siden.
- En gyldig signatur via «Hent offentlig nøkkel fra utsteder» beviser bare at tokenet er signert av den som kontrollerer URL-en i `iss`. Sjekk at du stoler på utstederen.

## Lisens

[Apache License 2.0](LICENSE)
