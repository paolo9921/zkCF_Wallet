pragma solidity ^0.8.20;


contract CA_Storage { 

    address private owner;
    mapping(bytes32 => bool) public publicKeys;
    //bytes[] public somePublicKeys;


    event NewPublicKeysStored(bytes[] publicKey);
    event LogPubkey(bytes32 public_Key);
    event LogPKBytes(bytes pk_bytes);
    event LogAdded(bool value);


    constructor(){//address _deployer) {
        //owner = _deployer;
        owner = msg.sender;
    }
    /**
    * Add public Keys array to storage
    * param newPubKeys array of pub key to add (bytes)
     */
    function addPublicKeys(bytes[] calldata newPubKeys) external onlyOwner {
        for (uint256 i = 0; i < newPubKeys.length ; i++) {
            bytes32 keyHash = keccak256(newPubKeys[i]);
            emit LogPKBytes(newPubKeys[i]);
            // if hash of the pubkey doesn't exists in mapping, add
            if (!publicKeys[keyHash]) {
                publicKeys[keyHash] = true;
                emit LogAdded(publicKeys[keyHash]);
            }

        }
        emit NewPublicKeysStored(newPubKeys);
    }
    
    
    function verifyPublicKey(bytes memory pubKey) external returns (bool exists){
        bytes32 keyHash = keccak256(pubKey);
        emit LogPubkey(keyHash);
        emit LogAdded(publicKeys[keyHash]);
        //return true;
        return publicKeys[keyHash];
    }

    modifier onlyOwner(){
        require(owner == msg.sender, "Ownership Assertion: Caller of the function is not the owner.");
        _;
    }


    //TEST
    
    function getOwner() public view returns (address) {
        return owner;   
    }

    
}   