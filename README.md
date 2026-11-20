# Bobologie Direction

Tableau de suivi pour les directeurs. Il complète l'appli Bobologie des animateurs : quand un bobo est « à surveiller » ou « à transmettre » aux parents ou à l'enseignant, le message WhatsApp de l'animateur contient un lien verrouillé que seule la direction peut ouvrir.

## Fonctionnement

- **Mot de passe direction** : choisi par le premier directeur, saisi une fois par téléphone. Il ne quitte jamais le téléphone.
- **Cadenas** : affiché dans les Réglages. Ce code n'est pas secret ; il est donné aux animateurs (Réglages → Lien direction de leur appli). Il leur permet de verrouiller les liens, pas de les rouvrir.
- **Recevoir les suivis** : dans WhatsApp, copier un ou plusieurs messages de bobologie, puis toucher « Coller les messages » dans l'appli. Sur Android, toucher le lien suffit aussi.
- **Traiter** : les suivis sont classés (enseignants, parents, à surveiller) et se cochent une fois faits. Un même bobo reçu deux fois n'est pas dupliqué.

Sans le mot de passe, la page ne montre rien : ni la liste des suivis, ni le contenu des liens.

## Confidentialité

Aucun serveur. Le contenu d'un lien est chiffré dans l'adresse elle-même (après le `#`, partie qui n'est jamais envoyée au site) et déchiffré sur le téléphone du directeur. Les suivis restent dans le stockage de l'appli.

Limite : la protection vaut ce que vaut le mot de passe. Choisir une phrase de quatre ou cinq mots, et ne pas l'écrire dans le groupe WhatsApp.

## Mise en ligne et installation

Même principe que l'appli animateur : GitHub Pages (Settings → Pages → Deploy from a branch → `main`, dossier `/ (root)`), puis ouvrir l'adresse dans Safari (iPhone) ou Chrome (Android) et ajouter l'appli à l'écran d'accueil. Sur iPhone, installer l'appli avant de saisir le mot de passe : l'appli installée a son propre stockage.

## Technique

Le mot de passe est transformé (PBKDF2-SHA-256) en clé privée P-256 ; le cadenas est la clé publique correspondante. Chaque lien est chiffré par ECDH éphémère + HKDF + AES-GCM, avec l'API Web Crypto du navigateur. Aucune dépendance, aucune étape de compilation.
