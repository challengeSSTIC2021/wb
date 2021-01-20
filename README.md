## Whitebox

Une whitebox camellia-128 avec suffix fixé.

Le but du challenge est soit:

- Changer le suffix de la whitebox pour un autre suffix. Cette attaque nécessite un oracle de déchiffrement de la whitebox.
- Casser la whitebox et extraire la clef. Peut être réalisé sans oracle mais relativement complexe.

La whitebox est placée dans une mini-vm. Le code et les tables de la VM sont mélangés dans une table.

# Utilisation

La lib fournit 2 fonctions:

- getSuffix: Permet de récupérer le suffix associé à la whitebox
- encryptVM: chiffre le message avec la clef de la whitebox. Les 8 derniers octets du message doivent être le suffix.

La whitebox n'est pas efficace pour chiffrer un message (doublement de la taille par rapport au clair), mais permet de signer un hash (de 8 bits) avec une clef et un suffix.

# Dépencance

- cmake >= 3.12
- make
- gcc ou clang
- python3
- python\_camellia (utiliser pour vérifier la whitebox lors du build)

# Compilation

```
mkdir whitebox_builder/build
cd whitebox_builder/build
cmake .. -DWB_SUFFIX=xxxxxxxxxxxxxxxx -DWB_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx -DWB_AESENC_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
make
```

WB\_SUFFIX correspond au suffix de la whitebox, WB\_KEY à la clef de la whitebox (pour camellia-128), WB\_AESENC\_KEY pour la clef
de chiffrement de la table de la whitebox.

# Protection

La table de la whitebox est chiffré avec AES-128-CTR et déchiffré par un constructeur. La clef AES est pour le moment
en clair. Cela permet de limiter l'analyse de la table si la lib n'est pas chargée.

# Protection possible

- Ajout de détection de ptrace dans le constructeur (corruption de la clef AES en cas de positif)
- Ajout de prctl(PR\_GET\_DUMPABLE) (le binaire est obligé de faire prctl(PR\_SET\_DUMPABLE) avant de charger la lib)
- Vérification d'intégrité (sur quoi, comment, ...)

# Ajustement de la difficulté

- Oracle de déchiffrement. Si les 8 premiers octets du clair ne sont pas un hash du message, le serveur renvoie le clair.
  Permet d'attaquer facilement le suffix.

- Une nouvelle whitebox générée toutes les 10 minutes, Whitebox valide que 20 minutes. La nouvelle whitebox a une nouvelle clef
  ce qui nécessite d'automatiser l'attaque sur la lib.

  Cela nécessite une compilation régulière de la whitebox, l'ajout d'un identifiant dans la whitebox (pour connaitre la clef correspondante),
  une gestion des clefs. Afin de ne pas géner un candidat dans son analyse, la whitebox devient invalide (ne permet pas de valider le chall) mais
  l'oracle reste opérationnel.

- Algo Camellia dans la VM. La VM inclus 3 fonctions supplémentaires qui ne sont pas exposé par la lib:

  - sheduleKey de camellia-128
  - encrypt de camellia-128 (à partir du résultat de sheduleKey)
  - decrypt de camellia-128 (à partir du résultat de sheduleKey)

  Ces trois fonctions n'utilisent pas la clef de la whitebox, ni le suffix et devraient permettre au concurrent de retrouver plus facilement l'algo de la whitebox
  avec une analyse des chemins de la VM.

  Peut être activé dans 'writer.py::VMWriter::__init__(addRawImplem=True)'

- En cas de génération régulière d'une nouvelle WB, changement des opcodes de la whitebox:

  Cela ne change que la valeur du premier octet de chaque opcode.

  Peut être activé dans 'writer.py::VMWriter::__init__(shuffleOpCode=True)'

- En cas de génération régulière d'une nouvelle WB, changement de l'ordre des opérandes de la whitebox:

  Pour les opcodes sur plusieurs octets, les octets sont mélangés (en dehors du premier)

  Peut être activé dans 'writer.py::VMWriter::__init__(shuffleOperand=True)'

