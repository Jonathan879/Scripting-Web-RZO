import requests
import socket
from bs4 import BeautifulSoup
import ssl
from scapy.all import *
import re

url = "https://taisen.fr"

# 1. Réaliser une requête Web GET sur un site Web
requete_Web = requests.get(url)

# 2. Afficher l'IP et le nom du serveur DNS qui résout le nom de domaine
Name_DNS = url.replace("https://", "").replace("http://", "").split("/")[0]
ip_address = socket.gethostbyname(Name_DNS)
print(f"IP Address: {ip_address}")
print(f"DNS Server: {Name_DNS}")

# 3. Afficher l'IP et le port Source 
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((Name_DNS, 443))
ip_source, port_source = sock.getsockname()
ip_dest, port_dest = sock.getpeername()
print(f"IP Source: {ip_source}")
print(f"Port Source: {port_source}")

# 4. Afficher l'IP et le port de destination
print(f"IP Destination: {ip_dest}")
print(f"Port Destination: {port_dest}")
sock.close()

# 5. Afficher les Headers, si le header est connu, alors afficher son utilité
print("\nHTTP Headers:")
headers_utilities = {
    "Content-Type": "Indique le type de média de la ressource envoyée au client.",
    "Content-Length": "Indique la taille du corps de la réponse, en octets.",
    "Server": "Contient des informations sur le logiciel du serveur qui gère la requête.",
    "Date": "Date et heure de la génération de la réponse.",
    "Connection": "Contrôle si la connexion réseau reste ouverte après l'envoi de la réponse.",
    "Cache-Control": "Directives de cache pour les caches à tous les niveaux entre client et serveur.",
    "Expires": "Donne la date/heure après laquelle la réponse est considérée périmée.",
    "Last-Modified": "Date et heure de la dernière modification de la ressource.",
    "Set-Cookie": "Envoie des cookies du serveur au client.",
}

for header, value in requete_Web.headers.items():
    utilite = headers_utilities.get(header, "Utilité inconnue.")
    print(f"{header}: {value} - {utilite}")

# 6. Afficher le Content-Type, s'il est générique, afficher son utilité
content_type = requete_Web.headers.get('Content-Type', 'Non spécifié')
if '/' in content_type:
    content_type_general = content_type.split('/')[0]
    content_type_utility = {
        'text': 'Texte plat, souvent utilisé pour HTML ou CSS.',
        'image': 'Image, souvent utilisé pour JPEG, PNG, etc.',
        'application': 'Type d\'application, comme JSON ou PDF.',
        'audio': 'Fichiers audio, comme MP3 ou WAV.',
        'video': 'Fichiers vidéo, comme MP4 ou AVI.'
    }.get(content_type_general.lower(), 'Type générique.')
else:
    content_type_utility = 'Type non spécifié.'

print(f"\nContent-Type: {content_type} - {content_type_utility}")

# 7. Stocker dans une variable de type tableau/Array les différentes balises Web
html_content = requete_Web.content
soup = BeautifulSoup(html_content, 'html.parser')
html_tags = [tag.name for tag in soup.find_all()]
print("\nHTML Tags:")
for tag in html_tags:
    print(tag)

# 8. Afficher les différents éléments du certificat SSL
cert = ssl.get_server_certificate((Name_DNS, 443))
x509 = ssl.PEM_cert_to_DER_cert(cert)
cert_info = ssl.DER_cert_to_PEM_cert(x509)
print(f"\nSSL Certificate Information:\n{cert_info}")

# 9. Afficher les noms de certificats de la chaîne de confiance
def get_certificate_issuer(url):
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=Name_DNS)
    conn.settimeout(5)
    
    try:
        conn.connect((Name_DNS, 443))
        cert = conn.getpeercert()
        issuer = dict(x[0] for x in cert['issuer'])
        print(f"Authority: {issuer['commonName']}")
    except Exception as e:
        print(f"Failed to retrieve certificate: {e}")
    finally:
        conn.close()

get_certificate_issuer(url)

# 10. Afficher la liste des IP équipements réseaux traversés pour atteindre le site Web
def traceroute(url, max_ttl=30):
    print(f"Traceroute vers {Name_DNS}:")
    for ttl in range(1, max_ttl + 1):
        pkt = IP(dst=Name_DNS, ttl=ttl) / ICMP()
        reply = sr1(pkt, verbose=0, timeout=1)
        if reply:
            print(f"{ttl}: {reply.src}")
            if reply.src == ip_address:
                break
        else:
            print(f"{ttl}: *")

traceroute(url)