import requests
import xml.etree.ElementTree as ET
from cryptography import x509
from web3 import Web3
import base64
from cryptography.hazmat.primitives import serialization
from typing import List, Dict, Optional

# Constants
LOTL_URL = "https://ec.europa.eu/tools/lotl/eu-lotl.xml"
WEB3_PROVIDER_URI = "http://localhost:8545"
CONTRACT_ADDRESS = "0x8464135c8f25da09e49bc8782676a84730c318bc"
PRIVATE_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" # must be the value of STORAGE_OWNER_KEY envvar

MY_CA_PK_HEX = "b9baeb42d2bec05bacb61ac7eb7cd639f07a84b011fe3875091bbf0427514b8d93d09cf9819bd47b64046ae5993ac12309e78913b4622f8d56c63f80ca7e834c1ad4f82a6d6e9bd5cc19817efe2408ef347e4e844de7b4ef33ef48bca03ea2f36c4f134b66d56c58efea2eb8cba56278f1f963c3fed611ee6159470ba0e55e6a778d52f2cc030dd8439472bb1ecbc55b5d40ff8b1e99de19cbb4954382fcecca147a9d91de759afbe12705cb1c6f2a2af64f17bd60a3036de68afd90ee2af1ac742534f52ebb09ae166c956ecd81a8c00e4a366edf412f01986875e96c5169492691924052f1d06288f97fd6cf2639a151edf63952c9f45cb0b86084d960e9f9"
MY_CA_PK = bytes.fromhex(MY_CA_PK_HEX)
# Contract ABI
CONTRACT_ABI = [
    {
        "inputs": [
            {
                "internalType": "bytes[]",
                "name": "publicKeys",
                "type": "bytes[]"
            }
        ],
        "name": "addPublicKeys",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [
            {
                "internalType": "bytes",
                "name": "publicKey",
                "type": "bytes"
            }
        ],
        "name": "verifyPublicKey",
        "outputs": [
            {
                "internalType": "bool",
                "name": "",
                "type": "bool"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    }
]

# XML Namespaces
NAMESPACES = {
    'tsl': 'http://uri.etsi.org/02231/v2#',
    'ns3': 'http://uri.etsi.org/02231/v2/additionaltypes#',
    'ns4': 'http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#',
    'ns5': 'http://uri.etsi.org/01903/v1.3.2#'
}

class TrustedCAFetcher:
    def __init__(self):
        self.web3 = Web3(Web3.HTTPProvider(WEB3_PROVIDER_URI))
        self.public_keys: List[bytes] = []
        
        if not self.web3.is_connected():
            raise ConnectionError("Failed to connect to Ethereum network")
            
        self.account = self.web3.eth.account.from_key(PRIVATE_KEY)
        self.contract = self.web3.eth.contract(
            address=self.web3.to_checksum_address(CONTRACT_ADDRESS),
            abi=CONTRACT_ABI
        )

    def get_trusted_lists(self) -> Optional[List[Dict]]:
        """Recupera e analizza la LOTL (List of Trusted Lists)"""
        try:
            response = requests.get(LOTL_URL, timeout=30)
            response.raise_for_status()
            root = ET.fromstring(response.content)

            trusted_lists = []
            pointers = root.findall('.//tsl:OtherTSLPointer', NAMESPACES)

            for pointer in pointers:
                tsl_url = pointer.find('.//tsl:TSLLocation', NAMESPACES)
                territory = pointer.find('.//tsl:SchemeTerritory', NAMESPACES)
                
                if tsl_url is not None and territory is not None and territory.text == 'IT':
                    trusted_lists.append({
                        'url': tsl_url.text,
                        'territory': territory.text
                    })
                    self.process_italian_tl(tsl_url.text)

            return trusted_lists

        except requests.exceptions.RequestException as e:
            print(f"Error downloading LOTL: {e}")
        except ET.ParseError as e:
            print(f"Error parsing XML: {e}")
        return None

    def process_italian_tl(self, tl_url: str) -> None:
        """Processa la Trusted List italiana ed estrae le chiavi pubbliche"""
        try:
            response = requests.get(tl_url, timeout=30)
            response.raise_for_status()
            root = ET.fromstring(response.content)

            tsps = root.findall('.//tsl:TrustServiceProvider', NAMESPACES)
            for tsp in tsps:
                services = tsp.findall('.//tsl:TSPService', NAMESPACES)
                for service in services:
                    self._extract_certificate(service)

        except requests.exceptions.RequestException as e:
            print(f"Error downloading Italian TL: {e}")
        except ET.ParseError as e:
            print(f"Error parsing Italian TL: {e}")

    def _extract_certificate(self, service: ET.Element) -> None:
        """Estrae e processa il certificato da un servizio"""
        cert_data = service.find('.//tsl:DigitalId/tsl:X509Certificate', NAMESPACES)
        if cert_data is not None:
            try:
                cert_bytes = base64.b64decode(cert_data.text)
                cert = x509.load_der_x509_certificate(cert_bytes)
                public_key = cert.public_key().public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                
                # Verifica se la chiave è già registrata prima di aggiungerla
                if not self.is_key_registered(public_key):
                    self.public_keys.append(public_key)
                    
            except Exception as e:
                print(f"Error processing certificate: {e}")

    def is_key_registered(self, public_key: bytes) -> bool:
        """Verifica se una chiave pubblica è già registrata nel contratto"""
        try:
            return False
            #return self.contract.functions.verifyPublicKey(public_key).call()
        except Exception as e:
            print(f"Error checking key registration: {e}")
            return False

    def send_to_contract(self, batch_size: int = 100) -> None:
        if not self.public_keys:
            print("No new public keys to send")
            return

        print(f"Using account: {self.account.address}")
        print(f"Contract address: {self.contract.address}")
        print(f"Chain ID: {self.web3.eth.chain_id}")
        print(f"Total keys to process: {len(self.public_keys)}")

        for i in range(0, len(self.public_keys), batch_size):
            batch = self.public_keys[i:i + batch_size]
            try:
                print(f"\nProcessing batch {i//batch_size + 1} with {len(batch)} keys")
                
                # Get latest nonce
                nonce = self.web3.eth.get_transaction_count(self.account.address)
                print(f"Current nonce: {nonce}")
                
                # Get gas price
                gas_price = self.web3.eth.gas_price
                print(f"Current gas price: {gas_price}")

                # Stima del gas utilizzando la funzione del contratto
                gas_estimate = self.contract.functions.addPublicKeys(batch).estimate_gas({
                    'from': self.account.address
                })
                print(f"Estimated gas: {gas_estimate}")

                # Costruisci la transazione usando la funzione del contratto
                transaction = self.contract.functions.addPublicKeys(batch).build_transaction({
                    'nonce': nonce,
                    'gasPrice': gas_price,
                    'gas': int(gas_estimate * 1.2),
                    'from': self.account.address,
                    'chainId': self.web3.eth.chain_id
                })
                
                # Firma la transazione
                signed = self.web3.eth.account.sign_transaction(transaction, private_key=PRIVATE_KEY)
                print("Transaction signed successfully")

                # Invia la transazione
                tx_hash = self.web3.eth.send_raw_transaction(signed.raw_transaction)
                print(f"Transaction sent: {tx_hash.hex()}")

                # Attendi la ricevuta
                receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
                print(f"Transaction confirmed in block {receipt['blockNumber']}")
                print(f"Gas used: {receipt['gasUsed']}")

            except Exception as e:
                print(f"Error processing batch {i//batch_size + 1}: {str(e)}")
                print("Transaction details:")
                print(f"From: {self.account.address}")
                print(f"To: {self.contract.address}")
                print(f"Nonce: {nonce}")
                print(f"Gas price: {gas_price}")
                print(f"Chain ID: {self.web3.eth.chain_id}")
                continue


def main():
    try:
        fetcher = TrustedCAFetcher()
        print("Starting Trusted Lists retrieval...")
        trusted_lists = fetcher.get_trusted_lists()

        if trusted_lists:
            print("\nFound Trusted Lists:")
            print(trusted_lists)
            print(f"Number of new public keys found: {len(fetcher.public_keys)}")
            if not fetcher.is_key_registered(MY_CA_PK):
                fetcher.public_keys.append(MY_CA_PK)
                print("\nMY CA KEY addedd. VALUE:")
                print(MY_CA_PK)
            else:
                print("My CA key already in contract.")     

            print(f"Number of new public keys found: {len(fetcher.public_keys)}")

            fetcher.send_to_contract()
            print("\naaaaa:\n")
            print(fetcher.public_keys[-1].hex())
        else:
            print("No trusted lists found or error occurred")
            
    except Exception as e:
        print(f"Error in main execution: {e}")


if __name__ == "__main__":
    main()