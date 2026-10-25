# Evidence Collector

## Avertissement Juridique / Legal Disclaimer

**FR :** Cet outil est une solution logicielle open-source conçue pour répondre aux exigences techniques de la norme AFNOR NF Z67-147. Pleinement fonctionnel et développé pour garantir une fiabilité technique optimale, ce logiciel constitue une aide à la collecte. Conformément à la législation française, seul un officier public ou ministériel (notamment le Commissaire de justice) est habilité à dresser un procès-verbal de constat doté d'une force probante devant les tribunaux. Les auteurs déclinent toute responsabilité quant à l'usage, l'interprétation ou les suites données à l'utilisation de cet outil dans le cadre de procédures ou de litiges réels.

**EN :** This tool is an open-source software solution designed to meet the technical requirements of the AFNOR NF Z67-147 standard. Fully functional and developed to ensure optimal technical reliability, this software serves as a collection aid. In accordance with French law, only a public or ministerial officer (specifically a Commissaire de justice) is authorized to draw up an official report (procès-verbal de constat) possessing evidentiary value before French courts. The authors disclaim all liability for the use, interpretation, or consequences arising from the use of this tool in the context of legal proceedings or actual disputes.

![EvidenceCollector Logo](ico/EvidenceCollector.jfif)

---

Outil de bureau Windows (C# / .NET 10, WinForms + Microsoft Edge WebView2) qui guide un commissaire de justice à travers les **quatre phases** d'une collecte de preuves sur Internet inspirée de la norme **AFNOR NF Z67-147**, et produit un dossier de preuves scellé et vérifiable.

> **Périmètre.** L'outil met en œuvre un flux de travail technique et enregistre les éléments nécessaires pour le démontrer. Il ne certifie pas lui-même la conformité à la norme : le commissaire de justice réalisant la collecte reste responsable de la méthode suivie et du procès-verbal. Ce même avertissement est affiché dans l'application (*À propos*).

* Interface utilisateur, journaux, info-bulles et messages : Anglais (en-US).
* Tous les paramètres sont stockés dans `config.json` (situé à côté de l'exécutable). Les commentaires et les virgules finales sont autorisés.
* Aucune télémétrie. Les seules connexions sortantes sont celles nécessaires à la collecte : le site visité, les serveurs NTP, les points de terminaison d'IP publique, WHOIS / RDAP.

---

## 1. Prérequis

| Composant | Exigence |
|---|---|
| Système d'exploitation | Windows 10 ou Windows 11, x64 ou ARM64 |
| SDK (pour la compilation) | **SDK .NET 10** (inclus dans Visual Studio 2026) |
| Runtime (pour l'exécution) | .NET 10 Desktop Runtime *ou* une publication autonome (voir §3) |
| Moteur de navigation | **Runtime Microsoft Edge WebView2** (Evergreen ; déjà présent sur Windows 11 et la plupart des machines Windows 10) – <https://developer.microsoft.com/microsoft-edge/webview2/> |
| Réseau | Sortie UDP 123 (NTP), TCP 43 (WHOIS) et HTTPS. Un port NTP ou WHOIS bloqué est signalé, non masqué. |

---

## 2. Structure du projet

```
EvidenceCollector/
├─ EvidenceCollector.csproj      net10.0-windows, WinForms, paquet WebView2, config.json copié vers la sortie
├─ Program.cs                    point d'entrée : --config <chemin>, boîte de dialogue de crash + crash.log
├─ config.json                   tous les paramètres, avec leur valeur par défaut et des commentaires
├─ config.schema.json            schéma JSON pour la validation / l'autoplcomplétion dans l'éditeur
│
├─ Config/
│  ├─ AppConfig.cs               modèle typé de config.json (chaque propriété a une valeur par défaut sûre)
│  └─ ConfigManager.cs           chargement, limitation des valeurs hors limites, mise à jour du thème, SHA-256 du fichier
│
├─ Core/                         moteur neutre vis-à-vis de la plateforme (couvert par les tests rapides)
│  ├─ HashEngine.cs              SHA-256 / SHA-512 en flux, une passe par fichier, tampons réutilisables
│  ├─ AuditLog.cs                piste d'audit en ajout seul, chaînée par hachage (audit.jsonl + audit.log)
│  ├─ Session.cs                 SessionContext, EvidenceRegistry (hachage à la création), statut des phases
│  ├─ NtpClient.cs, TimeSync.cs, TrustedClock.cs, ClockCheck.cs
│  │                             SNTP, plusieurs serveurs, décalage médian ; l'horloge du PC n'est jamais modifiée
│  ├─ EnvironmentChecker.cs      système, configuration, intégrité de l'outil, disque, temp, proxy, VPN, fichier hosts
│  ├─ NetworkDiagnostics.cs      cartes réseau (données ipconfig), serveurs DNS, IP publique par consensus, ipconfig / netsh bruts
│  ├─ NetworkPhaseRunner.cs      orchestration de la Phase 2
│  ├─ TargetDiagnostics.cs       réponse DNS, poignée de main TLS et certificat, traceroute optionnel pour l'hôte cible
│  ├─ WhoisClient.cs, WhoisCoordinator.cs      WHOIS (port 43, redirection IANA) avec secours RDAP ; domaine + IP
│  ├─ UrlValidator.cs            liste d'autorisations de schémas, normalisation, blocage optionnel des adresses privées
│  ├─ SecureTemp.cs              dossier temporaire privé par session, écrasement au mieux + suppression
│  └─ PhaseReports.cs, Models.cs, JsonUtil.cs, NetUtil.cs, AppInfo.cs
│
├─ Browser/
│  ├─ EvidenceBrowser.cs         enveloppe WebView2 : profil InPrivate, connexion directe, pas de cache, pas de téléchargements,
│  │                             autorisations refusées, une seule fenêtre, liste d'autorisations de schémas, audit complet de navigation
│  ├─ NetworkRecorder.cs         journal du protocole DevTools pour chaque requête / réponse (valeurs des cookies masquées)
│  ├─ PreparationRunner.cs       orchestration de la Phase 1 (vérifications + neutralisation des données du navigateur)
│  └─ PageScripts.cs
│
├─ Capture/
│  ├─ CaptureService.cs          captures de la Phase 3 (voir §4) ; chaque partie échoue indépendamment avec avertissement
│  └─ ScreenshotStamper.cs       bandeau d'information / filigrane : URL, heure UTC + locale, dossier, opérateur, session
│
├─ Sealing/
│  ├─ SealEngine.cs              Phase 4 : NTP, re-hachage complet, rapport, manifeste, reçu, ZIP, vérification
│  ├─ ManifestVerifier.cs        vérification autonome d'un paquet scellé
│  ├─ ReportGenerator.cs         rapport autonome encodé en HTML (annexe du procès-verbal)
│  └─ SealModels.cs
│
├─ UI/
│  ├─ MainForm.Designer.cs       TOUS les contrôles (compatible avec le concepteur Visual Studio)
│  ├─ MainForm.cs                comportement uniquement : verrouillage des phases, exécution du moteur, affichage des résultats
│  ├─ Theme.cs                   thème d'entreprise sombre / clair, listes personnalisées, barre de titre
│  └─ HeaderlessTabControl.cs    contrôle d'onglets sans barre d'onglets (piloté par la navigation des phases)
│
└─ tests/CoreSmokeTests/         tests de validation rapides neutres (57 vérifications, voir §7)
```

---

## 3. Compilation et exécution

### Ligne de commande

```powershell
# depuis le dossier contenant EvidenceCollector.csproj
dotnet --version                       # doit être en 10.x
dotnet restore
dotnet build -c Release
dotnet run -c Release                  # ou : .\bin\Release\net10.0-windows\EvidenceCollector.exe
dotnet run -c Release -- --config D:\cases\my-config.json     # fichier de configuration alternatif
```

### Visual Studio

Ouvrez `EvidenceCollector.csproj` (ou le dossier) dans une version de Visual Studio prenant en charge .NET 10, restaurez le paquet NuGet (`Microsoft.Web.WebView2`), puis appuyez sur **F5**. `UI\MainForm.cs` s'ouvre dans le concepteur Windows Forms : chaque contrôle est créé dans `MainForm.Designer.cs`, permettant de modifier la disposition visuellement sans toucher à la logique. Les noms des contrôles (`btnRunPrep`, `listEvidence`, …) sont utilisés par `MainForm.cs` ; conservez-les lors de vos renommages ou déplacements.

### Publication

```powershell
# autonome (rien à installer sauf le runtime WebView2)
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
```

Ne pas activer le découpage ("trimming", en raison de WinForms et du JSON fondé sur la réflexion). `config.json` et `config.schema.json` sont copiés à côté de l'exécutable ; modifiez `publish\config.json` pour le PC cible. Si `config.json` est absent et que le dossier n'est pas accessible en écriture (ex. `Program Files`), un fichier par défaut est créé dans `%LOCALAPPDATA%\EvidenceCollector\config.json`.

### Premier démarrage

1. Page **0 Session** : référence du dossier, opérateur, étude, objet → **Démarrer la session**. L'horloge est synchronisée, le dossier de session et le journal d'audit sont créés, puis le navigateur de preuve démarre.
2. Suivez les phases **1 → 4** à l'aide des boutons situés sur la gauche. Une phase ne s'ouvre que si la précédente a été validée (`workflow.enforcePhaseOrder`).

---

## 4. Les quatre phases

| Phase | Actions de l'application | Éléments inscrits dans le paquet |
|---|---|---|
| **0 Session** | Synchronisation NTP, dossier de session, journal d'audit, capture instantanée de `config.json` et de la configuration active | `00_session/` |
| **1 Préparation et neutralisation** | Vérification du poste de travail (système, fichier de configuration, intégrité de l'outil, espace disque libre, dossier temporaire, **horloge**, **proxy système**, **cartes VPN / tunnels**, fichier hosts). Effacement du cache, des cookies, du stockage local / session, d'IndexedDB, des service workers, de l'historique et du remplissage automatique, réinitialisation de l'historique, puis **vérification** du résultat (décompte des cookies avant / après). Le navigateur s'exécute en mode InPrivate, avec `--no-proxy-server` et le cache HTTP désactivé. Les détections de proxy / VPN sont affichées dans une bannière (politique : `Ignore`, `Warn` ou `Block` dans `config.json`). | `01_preparation/` |
| **2 Configuration réseau et diagnostics** | Configuration IP locale (cartes réseau, IPv4 / IPv6, passerelles, MAC), **serveurs DNS actifs**, **IP publique** confirmée par plusieurs points HTTPS indépendants, sortie brute de `ipconfig /all` et `netsh winhttp show proxy`, heure de référence NTP, titulaire WHOIS / RDAP de l'IP publique. | `02_network/` |
| **3 Navigation contrôlée et capture** | Barre d'URL validée ; fenêtre unique ; téléchargements et demandes d'autorisation refusés ; chaque navigation (y compris redirections et blocages) est enregistrée. Boutons de capture : **zone d'affichage** et **captures d'écran pleine page** (bandeau d'information avec URL, heure UTC, dossier et opérateur, plus filigrane diagonal ; le fichier PNG d'origine est conservé), **source** (corps brut de la réponse HTTP, en-têtes et chaîne de redirection, DOM rendu, texte visible, chaque fichier CSS tel que reçu, CSSOM), **archive** (MHTML + PDF), **connexion** (réponse DNS, poignée de main TLS et chaîne de certificats obtenue par le poste, cookies, journal complet des requêtes) et **WHOIS / RDAP** du domaine et de l'adresse du serveur. **Reneutraliser le navigateur…** nettoie le navigateur entre deux sites distincts. Capture automatique optionnelle après chaque chargement de page. La page est verrouillée contre toute navigation pendant l'exécution d'une capture afin d'en garantir l'unicité d'état. | `03_captures/<n>_<host>_<UTC>/`, `04_whois/` |
| **4 Clôture, intégrité et scellement** | Synchronisation NTP finale (heure officielle du scellement) ; chaque fichier enregistré est **re-haché** et comparé à l'empreinte prise lors de sa création ; un fichier non enregistré ou modifié **interrompt le scellement** ; rapport HTML ; journal d'audit clos ; `manifest.json`, `manifest.sha256`, reçu, ZIP optionnel + son empreinte SHA-256 ; fichiers passés en lecture seule ; le paquet scellé est vérifié à nouveau. | `05_sealing/`, `<session>.zip` |

### Horodatages

Chaque horodatage correspond à l'heure UTC corrigée par NTP **et** l'heure brute du PC est enregistrée à côté avec le décalage mesuré, permettant d'auditer la correction. L'horloge du PC n'est jamais modifiée. Si le serveur NTP est inaccessible, l'application le signale (`workflow.requireNtpSync` détermine si cela bloque la phase ou émet seulement un avertissement).

### Structure du dossier de session

```
<outputRoot>\EVC-20261024-101530-a1b2_<dossier>\
├─ 00_session\   session.json, config_snapshot.json, config_effective.json, navigation_trail.json
├─ 01_preparation\ 02_network\ 04_whois\
├─ 03_captures\0001_example.com_20261024T101712Z\   screenshots, source_*, css\, page_snapshot.mhtml, page_print.pdf,
│                                                    connection.json, cookies.json, network_resources.json, capture.json …
├─ audit\        audit.jsonl (chaîne de hachage), audit.log (lisible)
└─ 05_sealing\   manifest.json, manifest.sha256, SEAL_RECEIPT.txt, report.html
<outputRoot>\EVC-…_<dossier>.zip  et  .zip.sha256
```

**Reportez le SHA-256 du fichier `manifest.json` (affiché à la fin de la Phase 4 et dans `SEAL_RECEIPT.txt`) dans le procès-verbal.** Il constitue l'empreinte numérique de l'ensemble du paquet.

### Vérification ultérieure d'un paquet scellé

* Depuis l'application : page **0 Session → Vérifier un paquet…** (fonctionne sans démarrer de session), ou **Re-vérifier ce paquet** sur la page 4.
* Sans l'application : `manifest.sha256` est au format `sha256sum` → `sha256sum -c manifest.sha256` (Git Bash / WSL) ou `Get-FileHash -Algorithm SHA256 <fichier>` dans PowerShell.
* Le journal d'audit repose sur une chaîne de hachage : chaque entrée intègre l'empreinte de la précédente, et le hachage final est scellé dans le manifeste. Toute entrée insérée, modifiée, supprimée ou tronquée sera donc détectée.

---

## 5. `config.json`

Le fichier est complet : chaque option y figure avec sa valeur par défaut et un commentaire. Le fichier `config.schema.json` fournit la validation et l'autocomplétion dans Visual Studio / VS Code (grâce à la ligne `$schema` au sommet).

| Section | Paramètres contrôlés |
|---|---|
| `ui` | `theme` (`Dark` / `Light`, également basculable via le bouton d'en-tête, qui met à jour cette valeur sur place tout en conservant vos commentaires), `showAuditPanel` |
| `paths` | `outputRoot` (sessions), `tempRoot` (profil navigateur privé, nettoyé à la fin), `webViewRuntimeFolder` (version fixe du runtime). Les variables `%ENV%` sont développées |
| `session` | valeurs par défaut du formulaire de session, `requireCaseReference`, `requireOperatorName`, `sessionIdPrefix` |
| `workflow` | `enforcePhaseOrder`, `proxyPolicy` / `vpnPolicy` / `hostsFilePolicy` (`Ignore` / `Warn` / `Block`), `requirePublicIp`, `requireNtpSync`, `minimumFreeDiskMb` |
| `neutralization` | données de navigation effacées en Phase 1, suppression sécurisée des fichiers temporaires |
| `network` | points de terminaison d'IP publique (HTTPS uniquement) et seuil de consensus, délais d'expiration, mots-clés des cartes VPN, limites du traceroute |
| `ntp` | serveurs, délai d'expiration, échantillons par serveur, réponses minimales, erreur maximale tolérée de l'horloge système |
| `webView` | connexion directe, InPrivate, cache, langue, politique de pop-up, schémas autorisés, blocage d'adresses privées, téléchargements, DevTools, menu contextuel, user agent, taille du journal |
| `capture` | captures d'écran (tuiles, défilement automatique, incrustation), source, archive (MHTML / PDF, format de papier), cookies (les valeurs ne sont **pas** stockées par défaut), capture automatique, enregistrement de domaine (WHOIS / DNS / TLS / traceroute) |
| `whois` | serveur IANA, port, délais d'expiration, secours RDAP |
| `hashing` | `SHA256` toujours activé ; ajoutez `SHA512` pour un second condensat ; taille du tampon |
| `sealing` | ZIP, vérification post-scellement, fichiers en lecture seule, titre / organisation dans le rapport, vignettes |
| `logging` | écriture immédiate de chaque entrée, journal lisible, nombre de lignes conservées dans l'interface |

Les valeurs hors limites sont ajustées et **chaque correction est listée** dans une boîte de dialogue au démarrage. Un fichier impossible à analyser n'est jamais écrasé : les valeurs par défaut intégrées sont utilisées jusqu'à sa correction. La configuration réellement appliquée est sauvegardée dans le paquet (`config_effective.json`, accompagnée d'une copie du fichier d'origine : `config_snapshot.json`).

---

## 6. Sécurité et ressources

* **Isolation** – Le profil du navigateur réside dans un dossier spécifique à la session sous `paths.tempRoot` (accès restreint à l'utilisateur courant sur NTFS), en mode InPrivate, sans saisie automatique ni enregistrement de mot de passe, sans SSO avec le compte Windows. Les DevTools, le menu contextuel, les téléchargements et les autorisations sont désactivés/refusés. Les URL `javascript:`, `file:`, `data:` et `ftp:` ainsi que les fenêtres surgissantes sans action utilisateur sont bloquées. En fin de session, le profil est écrasé (au mieux, passe unique ; non garanti sur SSD ou volumes avec écriture sur copie) puis supprimé. Les profils résiduels d'une session interrompue (datant de plus d'un jour) sont nettoyés au démarrage suivant.
* **Intégrité** – Hachage en continu (une seule passe, tampon réutilisable, pas de lecture complète en mémoire), hachage dès la création puis re-hachage complet au scellement, journal d'audit chaîné par hachage écrit sur disque entrée par entrée, fichiers verrouillés en lecture seule après scellement.
* **Données sensibles** – Les valeurs de cookies et les identifiants sont masqués dans le journal des requêtes ; les valeurs des cookies ne sont enregistrées que si `capture.cookies.storeCookieValues` est défini sur `true`.
* **Empreinte système** – Poste de travail, ramasse-miettes (GC) non concurrent ; les corps de réponse conservés en mémoire sont plafonnés (`capture.source.maxCachedBodyMb`) ; le navigateur réduit son empreinte mémoire lorsqu'il est réduit ; la liste d'audit de l'interface est limitée. Les opérations lourdes (hachage, marquage d'image, ZIP) s'exécutent sur le pool de threads ; le thread d'interface pilotant uniquement WebView2.

---

## 7. Tests et vérifications effectuées

Le dossier `tests/CoreSmokeTests` regroupe les sources neutres vis-à-vis de la plateforme et s'exécute sur n'importe quel système d'exploitation :

```powershell
dotnet run --project tests/CoreSmokeTests          # 57 vérifications, code de sortie 0 = tout est validé
```

Ces tests couvrent le hachage (vecteurs FIPS), la logique NTP ainsi qu'un serveur NTP simulé, la validation d'URL, le chargement / l'ajustement de `config.json`, la chaîne d'audit (modification, suppression, tronquage), un cycle complet session → scellement → vérification (incluant le refus de sceller un fichier modifié ou non enregistré) et la détection d'altération sur un paquet scellé.

---

## 8. Dépannage

| Symptôme | Cause / Action à mener |
|---|---|
| "The Microsoft Edge WebView2 Runtime is not installed" | Installez le runtime Evergreen puis redémarrez l'application. |
| La Phase 1 ou la vérification de l'horloge **échoue** | NTP inaccessible (pare-feu bloquant le port UDP 123). Corrigez le blocage, ou passez `workflow.requireNtpSync` à `false` pour transformer l'erreur en avertissement – l'horloge du PC sera alors utilisée et le rapport le mentionnera. |
| Avertissement Proxy / VPN | La connexion n'est peut-être pas directe. Déconnectez-vous et relancez la Phase 1, ou justifiez cette situation dans le procès-verbal. Les clés `workflow.proxyPolicy` / `vpnPolicy` définissent le niveau de sévérité. |
| "Capture completed with warnings" | Une partie de la capture (par exemple le PDF) a échoué ; les autres éléments ont été enregistrés et l'écart est consigné dans `capture.json` ainsi que dans le journal d'audit. |
| Scellement refusé : "a file was modified / is not registered" | Un élément a été modifié ou ajouté dans le dossier de session après sa capture. Supprimez le fichier parasite ou restaurez l'original, puis relancez le scellement. |
| `config.json` ignoré | Le fichier contient une erreur de syntaxe : la boîte de dialogue au démarrage la détaille et les paramètres par défaut sont appliqués. |