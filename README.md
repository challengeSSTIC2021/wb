# Whitebox et service DRM client

Une whitebox camellia-128 avec suffix fixé utilisé lors du challenge SSTIC 2021 (https://www.sstic.org/2021/challenge/)
avec un plugin-client VLC.

Le but du challenge est soit:

- Changer le suffix de la whitebox pour un autre suffix. Cette attaque nécessite un oracle de déchiffrement de la whitebox.
- Casser la whitebox et extraire la clef. Peut être réalisé sans oracle mais relativement complexe.

La whitebox est placée dans une mini-vm. Le code et les tables de la VM sont mélangés dans une table.

## Organisation

- ``./client`` : l'implémentation du client VLC
- ``./key-server`` : une implémentation simple d'un serveur de clé (non utilisé lors du challenge)
- ``./nginx`` : fichiers pour le docker nginx
- ``./whitebox_builder`` : fichier pour le docker de compilation de la WB
- ``./solve_whitebox_pyqbdi`` : des scripts de solution basé sur PyQBDI pour extraire la whitebox

## Utilisation

### Compilation du module VLC

Dans le dossier client:

```
mkdir build
cd build
cmake ..
make
```

### Génération des fichiers statiques

1. Les fichiers qui seront disponibles dans vlc doivent être déposé dans ``key-server/files``.
2. Le fichier ``key-server/files.json`` doit être généré et doit contenir les informations sur chaque fichier à chiffrer:

```
[
    {
        "name": "<nom du fichier dans key-server/files>",
        "outdir": "<dossier de sortie dans le plugin vlc>",
        "type": "txt",
        "perms": 1
    }, {
        "name": "video_accessible_a_tous.mp4",
        "outdir": "./user0",
        "type": "mp4",
        "guest": null
    }
]
```

3. Lancer la commande ``./files-cipher.py --check --clean`` dans le dossier ``key-server``. Les fichiers sont maintenant chiffrés.

### Lancer les différents services

1. Changer la clef maître de la whitebox dans ``docker-compose.yaml``
2. Lancer les serveurs de contenu (nginx) et de compilation avec la commande ``docker-compose up -d``
3. Lancer le serveur de clef dans le dossier ``key-server`` avec ``./server.py -K <whitebox_master_key> -t 3600``

## Dépendance

Le challenge a été testé en juin 2021 sous archlinux avec les dépendances suivantes:

- docker version 20.10.6
- docker-compose version 1.29.1
- python 3.9.4
- python\_camellia
