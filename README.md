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

