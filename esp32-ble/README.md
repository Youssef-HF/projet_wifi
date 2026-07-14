# ESP32 BLE Red Team Controller

Outil de pentesting WiFi portable basé sur ESP32,
contrôlé via Bluetooth Low Energy depuis Kali Linux.

═══════════════════════════════════════════════════════════
RAPPORT TECHNIQUE — PROJET RED TEAM ESP32 BLE
═══════════════════════════════════════════════════════════

INFORMATIONS GÉNÉRALES
━━━━━━━━━━━━━━━━━━━━━━
Projet      : Outil de pentesting WiFi sur ESP32

═══════════════════════════════════════════════════════════
1. PRÉSENTATION DU PROJET
═══════════════════════════════════════════════════════════

Développement d'un outil de pentesting WiFi portable basé
sur un ESP32 DevKit, contrôlé à distance via Bluetooth Low
Energy depuis un poste Kali Linux.

Objectif : disposer d'un dispositif discret capable
d'effectuer des opérations de reconnaissance et d'audit
de sécurité WiFi dans un cadre de test d'intrusion autorisé.

ENVIRONNEMENT TECHNIQUE :

| Composant    | Détail                              |
|-------------|-------------------------------------|
| Hardware    | ESP32 DevKit V1                     |
| OS          | Kali Linux (ZSH)                   |
| Framework   | Arduino + PlatformIO                |
| Platform    | espressif32@3.5.0                   |
| ArduinoJson | v5.13.5 (StaticJsonBuffer)          |
| Communication | BLE GATT (2.4 GHz)               |
| Client      | Python 3 + bleak                    |

═══════════════════════════════════════════════════════════
2. ARCHITECTURE
═══════════════════════════════════════════════════════════

2.1 POURQUOI LE BLE COMME CANAL DE CONTRÔLE

Le BLE a été choisi comme canal principal car :
- Aucun conflit avec le WiFi (le WiFi reste 100% libre)
- Discret : nom BLE = "Galaxy S23 Prime+" (se fond dans la masse)
- Sans fil : portée 10-30 mètres
- Kali conserve sa connexion internet normale

Alternatives écartées :
- USB Serial : câble physique obligatoire, pas discret
- WiFi AP : conflit direct avec les opérations WiFi offensives
- WiFi STA : même problème de conflit de canal

2.2 STRUCTURE DES FICHIERS

~/Projet-TC/ESP-32/red-esp32/
├── platformio.ini       (configuration build)
└── src/
    ├── config.h         (paramètres configurables)
    └── main.cpp         (code source ~1800 lignes)

~/Projet-TC/ESP-32/
├── red_team_ble.py      (client Python BLE ~700 lignes)
└── captures/
    ├── capture_*.pcap   (handshakes PCAP)
    ├── capture_*.json   (données brutes)
    ├── sniff_*.json     (rapports sniffer)
    ├── pmkid_*.txt      (hashes PMKID)
    └── portal_creds.txt (credentials capturés)

2.3 SÉCURITÉ DE LA COMMUNICATION

- PIN obligatoire à chaque connexion (défaut : 9876)
- Timeout 30 secondes pour saisir le PIN
- Maximum 3 tentatives puis déconnexion forcée
- MAC WiFi randomisée à chaque démarrage

═══════════════════════════════════════════════════════════
3. FONCTIONNALITÉS ET UTILISATION
═══════════════════════════════════════════════════════════

LANCEMENT DU CLIENT :

    python3 ~/Projet-TC/ESP-32/red_team_ble.py

MENU PRINCIPAL :

    +==========================================+
    |       RED ESP32 - BLE Console            |
    +==========================================+
    |  RECON                                   |
    |   1.  WiFi Scan                          |
    |   2.  Sniffer (canal fixe)               |
    |   3.  Sniffer filtré par BSSID           |
    |   4.  Sniffer Channel Hopping (1-13)     |
    |   5.  Handshake Capture -> PCAP          |
    |   6.  PMKID Capture                      |
    +------------------------------------------+
    |  OFFENSIF                                |
    |   7.  Beacon Spam - Liste SSIDs          |
    |   8.  Beacon Spam - Aléatoire            |
    |   9.  Evil Portal                        |
    |   10. Evil Twin (Rogue AP)               |
    |   11. Karma Attack                       |
    +------------------------------------------+
    |   12. Status ESP32                       |
    |   13. Stop attaque en cours              |
    |   0.  Quitter                            |
    +==========================================+

─────────────────────────────────────────────
3.1 WIFI SCAN (choix 1)
─────────────────────────────────────────────
Description : scan tous les réseaux WiFi environnants.

Utilisation :
    Choice > 1
    → Résultat JSON avec SSID, BSSID, RSSI, Canal, Chiffrement

Exemple de résultat :
    {
      "status": "ok",
      "count": 12,
      "networks": [
        {"ssid": "Livebox-1234", "bssid": "AA:BB:CC:DD:EE:FF",
         "rssi": -45, "channel": 11, "enc": 4}
      ]
    }

─────────────────────────────────────────────
3.2 SNIFFER CANAL FIXE (choix 2)
─────────────────────────────────────────────
Description : écoute passive sur un canal. Invisible et
indétectable. Collecte les APs, clients et probe requests.

Utilisation :
    Choice > 2
    Channel (1) > 6
    → Stats toutes les 5 secondes
    → ENTER pour stopper et recevoir le rapport complet
    → Rapport sauvegardé : captures/sniff_TIMESTAMP.json

─────────────────────────────────────────────
3.3 SNIFFER FILTRÉ PAR BSSID (choix 3)
─────────────────────────────────────────────
Description : sniffer ciblant un routeur précis.

Utilisation :
    Choice > 3
    BSSID > AA:BB:CC:DD:EE:FF
    Channel > 6
    → Affiche uniquement le trafic de ce routeur
    → "matched" = paquets impliquant ce BSSID

─────────────────────────────────────────────
3.4 CHANNEL HOPPING (choix 4)
─────────────────────────────────────────────
Description : rotation automatique sur les canaux 1-13.
Cartographie complète de l'environnement WiFi.

Utilisation :
    Choice > 4
    → Change de canal toutes les 500ms automatiquement
    → ENTER pour stopper et recevoir le rapport complet

─────────────────────────────────────────────
3.5 HANDSHAKE CAPTURE (choix 5)
─────────────────────────────────────────────
Description : capture le handshake WPA4 voies d'un réseau.
Nécessite qu'un appareil se connecte/reconnecte au réseau cible.

Utilisation :
    Choice > 5
    BSSID > AA:BB:CC:DD:EE:FF    (depuis le scan)
    Channel > 11
    → Déconnecter/reconnecter un appareil WiFi cible
    → Notification à chaque frame EAPOL capturée :
       [EAPOL] M1/4 capturé (+340ms)
       [EAPOL] M2/4 capturé (+380ms)
       [EAPOL] M3/4 capturé (+420ms)
       [EAPOL] M4/4 capturé (+460ms)
    → Message quand complet :
       ✅ HANDSHAKE CAPTURÉ — appuyez ENTER pour sauvegarder
    → ENTER pour transférer et sauvegarder
    → Fichiers : capture_BSSID_TIMESTAMP.pcap + .json

Validation et crack :
    hcxpcapngtool capture.pcap -o capture.hc22000
    hashcat -m 22000 capture.hc22000 wordlist.txt

─────────────────────────────────────────────
3.6 PMKID CAPTURE (choix 6)
─────────────────────────────────────────────
Description : capture le PMKID depuis les beacons du routeur.
Ne nécessite PAS qu'un client se connecte.

Utilisation :
    Choice > 6
    BSSID (vide=tous) > AA:BB:CC:DD:EE:FF
    Channel > 6
    → ENTER pour stopper
    → Hash WPA*01 généré automatiquement
    → Sauvegardé : captures/pmkid_TIMESTAMP.txt

Crack :
    hashcat -m 22000 pmkid.txt wordlist.txt

─────────────────────────────────────────────
3.7 BEACON SPAM LISTE (choix 7)
─────────────────────────────────────────────
Description : crée de faux réseaux WiFi avec des SSIDs définis.

Utilisation :
    Choice > 7
    SSIDs (ligne vide pour finir) :
      > FreeWifi
      > Airport_Guest
      > Hotel_WiFi
      >               ← ligne vide pour finir
    Channel > 1
    → Choix 13 pour stopper

─────────────────────────────────────────────
3.8 BEACON SPAM ALÉATOIRE (choix 8)
─────────────────────────────────────────────
Description : génère N faux réseaux avec des noms aléatoires.

Utilisation :
    Choice > 8
    Nombre SSIDs (20) > 15
    Channel > 6
    → Choix 13 pour stopper

─────────────────────────────────────────────
3.9 EVIL PORTAL (choix 9)
─────────────────────────────────────────────
Description : crée un faux point d'accès WiFi avec une page
de capture de mot de passe. Fonctionne sur mobile (Android/iOS).

Utilisation :
    Choice > 9
    SSID (Free_WiFi) > MonReseau
    Password (vide=open) >       ← laisser vide pour réseau ouvert
    Channel (6) > 6
    → Appareil se connecte au réseau "MonReseau"
    → Page de login s'ouvre automatiquement (captive portal)
    → L'utilisateur entre son mot de passe WiFi
    → Credential affiché instantanément :
       PASSWORD CAPTURED!
       SSID     : MonReseau
       Password : test1234
       IP       : 192.168.4.2
    → ENTER pour stopper
    → Sauvegardé : captures/portal_creds.txt

─────────────────────────────────────────────
3.10 EVIL TWIN (choix 10)
─────────────────────────────────────────────
Description : clone exact d'un réseau existant. Plus efficace
que l'Evil Portal car utilise le même nom que le vrai réseau.

Utilisation :
    Choice > 1   ← scanner d'abord pour trouver le SSID exact
    Choice > 10
    SSID du reseau a cloner > Livebox-1234
    Channel > 11
    → L'ESP32 crée un réseau "Livebox-1234"
    → Les appareils se connectent (même nom que le vrai)
    → Page de capture du mot de passe
    → ENTER pour stopper

─────────────────────────────────────────────
3.11 KARMA ATTACK (choix 11)
─────────────────────────────────────────────
Description : répond aux Probe Requests des appareils en se
faisant passer pour les réseaux qu'ils cherchent.

Utilisation :
    Choice > 11
    Channel > 1
    → Désactiver/réactiver le WiFi sur un téléphone
    → Affiche les réseaux cherchés :
       [KARMA] F0:D4:15:6B:56:C5 cherche 'Livebox-1234'
       [KARMA] 3E:A6:E6:68:57:14 cherche 'iPhone de X'
    → ENTER pour stopper

═══════════════════════════════════════════════════════════
4. PROTOCOLE BLE JSON
═══════════════════════════════════════════════════════════

COMMANDES (Kali → ESP32) :

| Commande              | Paramètres              |
|----------------------|-------------------------|
| {"pin":"9876"}       | Authentification        |
| {"cmd":"scan"}       | Scan WiFi               |
| {"cmd":"sniffer"}    | channel, bssid (opt)    |
| {"cmd":"hop_sniffer"}| -                       |
| {"cmd":"handshake"}  | bssid, channel          |
| {"cmd":"pmkid"}      | channel, bssid (opt)    |
| {"cmd":"beacon"}     | ssids ou mode+count     |
| {"cmd":"portal"}     | ssid, channel           |
| {"cmd":"evil_twin"}  | ssid, channel           |
| {"cmd":"karma"}      | channel                 |
| {"cmd":"stop"}       | Arrêt de toute attaque  |
| {"cmd":"status"}     | État du système         |

═══════════════════════════════════════════════════════════
5. PROBLÈME MAJEUR : INJECTION DEAUTH BLOQUÉE
═══════════════════════════════════════════════════════════

5.1 DESCRIPTION

L'attaque Deauth nécessite l'injection de trames management :
- 0xC0 = Deauth
- 0xA0 = Disassoc

Ces types sont bloqués par le SDK Espressif IDF 4.x.

5.2 ERREURS OBSERVÉES

    E (xxxxx) wifi:unsupport frame type: 0c0
    E (xxxxx) wifi:unsupport frame type: 0a0
    [TX] err=0x102       → ESP_ERR_INVALID_ARG
    [TX] err=0xfffffff0  → ESP_ERR_WIFI_IF

5.3 TENTATIVES DE CONTOURNEMENT

| Méthode                        | Résultat              |
|--------------------------------|-----------------------|
| esp_wifi_internal_tx() STA     | Erreur 0x102 — bloqué |
| esp_wifi_80211_tx() STA        | Erreur 0x102 — bloqué |
| esp_wifi_80211_tx() AP         | Erreur + BLE déco     |
| en_sys_seq=true                | Erreur 0xfffffff0     |
| Patch registre MAC hardware    | Filtre est SOFTWARE   |
| ieee80211_freedom_init()       | Signature incompatible|
| Analyse libnet80211.a          | API interne inaccessible|

5.4 CONCLUSION

Le filtre est une restriction volontaire d'Espressif dans
IDF 4.x, implémentée au niveau SOFTWARE dans le SDK.
Impossible à contourner proprement sur espressif32@3.5.0
sans compromettre la stabilité du BLE.

Note : les trames Beacon (0x80) et Probe Response (0x50)
ne sont pas filtrées, ce qui permet le Beacon Spam, Evil
Portal, Evil Twin et Karma Attack.

═══════════════════════════════════════════════════════════
6. RÉSULTATS DES TESTS
═══════════════════════════════════════════════════════════

| Fonctionnalité        | Résultat | Note                     |
|----------------------|----------|--------------------------|
| Auth BLE + PIN       | ✅       | Timeout + blacklist OK   |
| WiFi Scan            | ✅       | 20+ réseaux détectés     |
| Sniffer canal fixe   | ✅       | 4685 paquets / 50s       |
| Sniffer filtré BSSID | ✅       | 531/4685 matchés         |
| Channel Hopping      | ✅       | Canaux 1-13 automatique  |
| Handshake WPA        | ✅       | PCAP validé, hash cracké |
| PMKID Capture        | ✅       | Hash WPA*01 généré       |
| Beacon Spam          | ✅       | Visible sur les scanners |
| Evil Portal          | ✅       | Credentials capturés     |
| Evil Twin            | ✅       | Password capturé         |
| Karma Attack         | ✅       | Probes interceptées      |
| MAC randomisée       | ✅       | Nouvelle MAC chaque boot |
| Deauth Attack        | ❌       | Bloqué par SDK IDF 4.x   |

═══════════════════════════════════════════════════════════
7. CONCLUSION
═══════════════════════════════════════════════════════════

Ce projet démontre qu'un ESP32 à faible coût peut constituer
un outil de pentesting WiFi capable et discret. Le canal BLE
permet un contrôle sans fil tout en laissant le WiFi libre
pour les opérations d'audit.

La principale limitation — l'impossibilité d'injecter des
frames Deauth — est une restriction du SDK Espressif qui ne
peut être contournée sur cette version sans compromettre
la stabilité du BLE.

L'ensemble des fonctionnalités de reconnaissance passive et
d'audit offensif offre un outil cohérent pour des tests de
sécurité WiFi en environnement autorisé.
 
## Prérequis

- ESP32 DevKit V1
- Kali Linux avec PlatformIO
- Python 3 + bleak

```bash
pip install bleak

"
