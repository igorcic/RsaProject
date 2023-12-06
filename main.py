import base64

from RSAkeygenerator import RSAKeyGenerator
from RSAsignatare import RSASignatureGenerator


class Menu:
    def __init__(self):
        self.rsa_key_generator = RSAKeyGenerator()
        self.private_key = self.rsa_key_generator.get_private_key()
        self.public_key = self.rsa_key_generator.get_public_key()
        self.signature_generator = RSASignatureGenerator(self.public_key, self.private_key, label=b'MyLabel')

    def show_main_menu(self):
        while True:
            print("\n# -------------------- Menu Principal -------------------- #")
            print("1. Geração de chaves RSA")
            print("2. Assinatura RSA")
            print("3. Sair")

            choice = input("Escolha uma opção (1, 2, ou 3): ")

            if choice == '1':
                self.generate_rsa_keys_menu()
            elif choice == '2':
                self.generate_rsa_signature_menu()
            elif choice == '3':
                print("Saindo do programa.")
                break
            else:
                print("Opção inválida. Tente novamente.")

    def generate_rsa_keys_menu(self):
        print("\n# -------------------- Parte I: Geração de chaves -------------------- #")
        print("* 1. Geração de chaves (p e q primos com no mínimo de 1024 bits):")
        print("  - p com teste de primalidade (Miller-Rabin) =", self.rsa_key_generator.p)
        print("  - q  com teste de primalidade (Miller-Rabin) =", self.rsa_key_generator.q)
        print("  - Chave privada:", self.private_key)
        print("  - Chave pública:", self.public_key)

        message = input("\n* Insira a mensagem para cifragem: ")

        # Cifragem usando a chave pública
        encrypted_message = self.rsa_key_generator.rsa_encrypt(message, self.public_key)
        print("* Mensagem cifrada:", encrypted_message)

        # Decifragem usando a chave privada
        decrypted_message = self.rsa_key_generator.rsa_decrypt(encrypted_message, self.private_key)
        print("* Mensagem decifrada:", decrypted_message)

    def generate_rsa_signature_menu(self):
        message = input("\n* Insira a mensagem para assinatura: ")

        print("* 1. Cálculo de hashes da mensagem em claro (função de hash SHA-3):")
        resultado_sha = self.signature_generator.sha3_224(message.encode('utf-8'))
        print('  - SHA3_224 =', base64.encodebytes(resultado_sha))

        print("* 2. Assinatura da mensagem (cifração do hash da mensagem usando OAEP):")
        assinatura = self.signature_generator.assina_mensagem(message)
        print("  - Assinatura da mensagem =", assinatura)


if __name__ == "__main__":
    menu = Menu()
    menu.show_main_menu()
