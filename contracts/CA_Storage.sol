pragma solidity ^0.8.20;


contract CA_Storage { 

    address private owner;
    mapping(bytes32 => bool) public publicKeys;
    //bytes[] public somePublicKeys;
    uint256 public publicKeyCount = 0;


    event NewPublicKeysStored(bool result);
    event LogPubkey(bytes32 public_Key);
    event LogPKBytes(bytes pk_bytes);


    constructor(){//address _deployer) {
        //owner = _deployer;
        owner = msg.sender;
    }
    /**
    * @dev Add public Keys array to storage
    * @param newPubKeys array of (bytes) pub key to add
     */
    function addPublicKeys(bytes[] calldata newPubKeys) external onlyOwner {
        for (uint256 i = 0; i < newPubKeys.length ; i++) {
            bytes32 keyHash = keccak256(newPubKeys[i]);
            // if hash of the pubkey doesn't exists in mapping, add
            if (!publicKeys[keyHash]) {
                publicKeyCount++;
                publicKeys[keyHash] = true;
            }

        }
        emit NewPublicKeysStored(true);
    }
    
    
    function verifyPublicKey(bytes memory pubKey) external view returns (bool exists){
        bytes32 keyHash = keccak256(pubKey);
        return publicKeys[keyHash];
    }

    modifier onlyOwner(){
        require(owner == msg.sender, "Ownership Assertion: Caller is not the owner");
        _;
    }


    //TEST
    
    function getOwner() public view returns (address) {
        return owner;   
    }

    /**
     * @dev Modificatore per verificare se il chiamante è un smart contract.
     */
    modifier onlyContract() {
        require(isContract(msg.sender), "CfWallet: caller is not a contract");
        _;
    }

    /**
     * @dev Funzione interna per verificare se un indirizzo è un contratto.
     * @param _addr L'indirizzo da verificare.
     * @return True se l'indirizzo è un contratto, altrimenti false.
     */
    function isContract(address _addr) internal view returns (bool) {
        uint32 size;
        assembly {
            size := extcodesize(_addr)
        }
        return (size > 0);
    }

    
}   