// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "./Pairing.sol";

contract BLSSafe is Ownable {
    using SafeERC20 for IERC20;

    bool public IsActive = false;

    uint64 public nextSignerID = 1;
    uint64 public constant LIST_END = type(uint64).max;

    uint256 public totalSigners = 0;
    uint256 public blsNonSignerThreshold = 0;

    string public proofOfPossessionTag;
    string public addTag;
    string public removalTag;
    string public transferTag;


    constructor() Ownable(msg.sender) {
        proofOfPossessionTag = buildTag("BLS_SIG_TRYANDINCREMENT_POP");
        addTag = buildTag("BLS_SIG_TRYANDINCREMENT_ADD");
        removalTag = buildTag("BLS_SIG_TRYANDINCREMENT_REMOVE");
        transferTag = buildTag("BLS_SIG_TRYANDINCREMENT_TRANSFER");

        signers[LIST_END].previous = LIST_END;
        signers[LIST_END].next = LIST_END;
    }

    /// @dev Builds a tag string using a base tag and contract-specific information. This is used when signing messages to prevent reuse of signatures across different domains (chains/functions/contracts)
    /// @param baseTag The base string for the tag.
    /// @return The constructed tag string.
    function buildTag(string memory baseTag) private view returns (string memory) {
        return string(abi.encodePacked(baseTag, block.chainid, address(this)));
    }

    /// @notice Represents a signer of the safe.
    struct Signer {
        uint64 next;
        uint64 previous;
        BN256G1.G1Point pubkey;
    }

    mapping(uint64 => Signer) public signers;
    mapping(bytes32 => uint64) public signerIDs;

    BN256G1.G1Point public aggregate_pubkey;

    // EVENTS
    event NewSeededSigner(uint64 indexed signerID, BN256G1.G1Point pubkey);
    event NewSigner(uint64 indexed signerID, BN256G1.G1Point pubkey);
    event SignerRemoval(uint64 indexed signerID, BN256G1.G1Point pubkey);

    // ERRORS
    error BLSPubkeyAlreadyExists(uint64 signerID);
    error SignerDoesntExist(uint64 signerID);
    error InvalidBLSSignature();
    error InvalidBLSProofOfPossession();
    error ArrayLengthMismatch();
    error InvalidParameter();
    error InsufficientBLSSignatures(uint256 numSigners, uint256 requiredSigners);
    error InsufficientBalance();
    error ContractNotActive();

    /// @notice Adds a BLS public key to the list of signers. Requires a proof of possession BLS signature to prove user controls the public key being added
    /// @param pkX X-coordinate of the public key.
    /// @param pkY Y-coordinate of the public key.
    /// @param sigs0 First part of the proof of possession signature.
    /// @param sigs1 Second part of the proof of possession signature.
    /// @param sigs2 Third part of the proof of possession signature.
    /// @param sigs3 Fourth part of the proof of possession signature.
    function addSigner(uint256 pkX, uint256 pkY, uint256 sigs0, uint256 sigs1, uint256 sigs2, uint256 sigs3) public {
        if (!IsActive) revert ContractNotActive();
        BN256G1.G1Point memory pubkey = BN256G1.G1Point(pkX, pkY);
        uint64 signerID = signerIDs[BN256G1.getKeyForG1Point(pubkey)];
        if(signerID != 0) revert BLSPubkeyAlreadyExists(signerID);
        validateProofOfPossession(pubkey, sigs0, sigs1, sigs2, sigs3);
        uint64 previous = signers[LIST_END].previous;

        /*signers[nextSignerID] = Signer(previous, recipient, pubkey, LIST_END);*/
        signers[previous].next = nextSignerID;
        signers[nextSignerID].previous = previous;
        signers[nextSignerID].next = LIST_END;
        signers[nextSignerID].pubkey = pubkey;
        signers[LIST_END].previous = nextSignerID;

        signerIDs[BN256G1.getKeyForG1Point(pubkey)] = nextSignerID;

        if (signers[LIST_END].next != LIST_END) {
            aggregate_pubkey = BN256G1.add(aggregate_pubkey, pubkey);
        } else {
            aggregate_pubkey = pubkey;
        }
        totalSigners++;
        updateBLSThreshold();
        emit NewSigner(nextSignerID, pubkey);
        nextSignerID++;
    }

    /// @notice Validates the proof of possession for a given BLS public key.
    /// @param pubkey The BLS public key.
    /// @param sigs0 First part of the proof of possession signature.
    /// @param sigs1 Second part of the proof of possession signature.
    /// @param sigs2 Third part of the proof of possession signature.
    /// @param sigs3 Fourth part of the proof of possession signature.
    function validateProofOfPossession(BN256G1.G1Point memory pubkey, uint256 sigs0, uint256 sigs1, uint256 sigs2, uint256 sigs3) internal {
        BN256G2.G2Point memory Hm = BN256G2.hashToG2(BN256G2.hashToField(string(abi.encodePacked(proofOfPossessionTag, pubkey.X, pubkey.Y))));
        BN256G2.G2Point memory signature = BN256G2.G2Point([sigs1,sigs0],[sigs3,sigs2]);
        if (!Pairing.pairing2(BN256G1.P1(), signature, BN256G1.negate(pubkey), Hm)) revert InvalidBLSProofOfPossession();
    }

    function removeSigner(uint64 signerID, uint256 sigs0, uint256 sigs1, uint256 sigs2, uint256 sigs3, uint64[] memory ids) external {
        if (!IsActive) revert ContractNotActive();
        if (ids.length > blsNonSignerThreshold) revert InsufficientBLSSignatures(signersLength() - ids.length, signersLength() - blsNonSignerThreshold);
        //Validating signature
        BN256G2.G2Point memory Hm = BN256G2.hashToG2(BN256G2.hashToField(string(abi.encodePacked(removalTag, signerID))));
        BN256G1.G1Point memory pubkey;
        for(uint256 i = 0; i < ids.length; i++) {
            pubkey = BN256G1.add(pubkey, signers[ids[i]].pubkey);
        }
        pubkey = BN256G1.add(aggregate_pubkey, BN256G1.negate(pubkey));
        BN256G2.G2Point memory signature = BN256G2.G2Point([sigs1,sigs0],[sigs3,sigs2]);
        if (!Pairing.pairing2(BN256G1.P1(), signature, BN256G1.negate(pubkey), Hm)) revert InvalidBLSSignature();

        _removeSigner(signerID);
    }

    function _removeSigner(uint64 signerID) internal {
        uint64 previousSigner = signers[signerID].previous;
        uint64 nextSigner = signers[signerID].next;
        if (nextSigner == 0) revert SignerDoesntExist(signerID);

        signers[previousSigner].next = nextSigner;
        signers[nextSigner].previous = previousSigner;

        BN256G1.G1Point memory pubkey = BN256G1.G1Point(signers[signerID].pubkey.X, signers[signerID].pubkey.Y);

        aggregate_pubkey = BN256G1.add(aggregate_pubkey, BN256G1.negate(pubkey));

        delete signers[signerID].previous;
        delete signers[signerID].next;
        delete signers[signerID].pubkey.X;
        delete signers[signerID].pubkey.Y;

        delete signerIDs[BN256G1.getKeyForG1Point(pubkey)];

        totalSigners--;
        updateBLSThreshold();

        emit SignerRemoval(signerID, signers[signerID].pubkey);
    }

    function seedSignerList(uint256[] calldata pkX, uint256[] calldata pkY) public onlyOwner {
        if (pkX.length != pkY.length) revert ArrayLengthMismatch();
        uint64 lastSigner = signers[LIST_END].previous;

        bool firstSigner = signersLength() == 0;

        for(uint256 i = 0; i < pkX.length; i++) {
            BN256G1.G1Point memory pubkey = BN256G1.G1Point(pkX[i], pkY[i]);
            bytes32 pubkeyhash = BN256G1.getKeyForG1Point(pubkey);
            uint64 signerID = signerIDs[pubkeyhash];
            if(signerID != 0) revert BLSPubkeyAlreadyExists(signerID);

            /*signers[nextSignerID] = Signer(previous,  pubkey, LIST_END);*/
            signers[lastSigner].next = nextSignerID;
            signers[nextSignerID].previous = lastSigner;
            signers[nextSignerID].pubkey = pubkey;

            signerIDs[pubkeyhash] = nextSignerID;

            if (!firstSigner) {
                aggregate_pubkey = BN256G1.add(aggregate_pubkey, pubkey);
            } else {
                aggregate_pubkey = pubkey;
                firstSigner = false;
            }

            emit NewSeededSigner(nextSignerID, pubkey);
            lastSigner = nextSignerID;
            nextSignerID++;
        }

        signers[lastSigner].next = LIST_END;
        signers[LIST_END].previous = lastSigner;

        totalSigners++;
        updateBLSThreshold();
    }

    function signersLength() public view returns (uint256 count) {
        uint64 currentSigner = signers[LIST_END].next;
        count = 0;

        while (currentSigner != LIST_END) {
            count++;
            currentSigner = signers[currentSigner].next;
        }

        return count;
    }

    function updateSignersLength() public {
        totalSigners = signersLength();
    }

    /// @notice Updates the internal threshold for how many non signers an aggregate signature can contain before being invalid
    function updateBLSThreshold() internal {
        if (totalSigners > 900) {
            blsNonSignerThreshold = 300;
        } else {
            blsNonSignerThreshold = totalSigners / 3;
        }
    }

    /// @notice Contract begins paused and owner can start after signers have been added
    function start() public onlyOwner {
        IsActive = true;
    }


    function transferWithBLSSignature(
        address payable recipient,
        uint256 amount,
        uint256 sigs0,
        uint256 sigs1,
        uint256 sigs2,
        uint256 sigs3,
        uint64[] memory ids
    ) external {
        if (!IsActive) revert ContractNotActive();
        if (ids.length > blsNonSignerThreshold) revert InsufficientBLSSignatures(signersLength() - ids.length, signersLength() - blsNonSignerThreshold);
        if (amount > address(this).balance) revert InsufficientBalance();

        BN256G2.G2Point memory Hm = BN256G2.hashToG2(BN256G2.hashToField(string(abi.encodePacked(transferTag, recipient, amount))));
        BN256G1.G1Point memory pubkey;
        for (uint256 i = 0; i < ids.length; i++) {
            pubkey = BN256G1.add(pubkey, signers[ids[i]].pubkey);
        }
        pubkey = BN256G1.add(aggregate_pubkey, BN256G1.negate(pubkey));
        BN256G2.G2Point memory signature = BN256G2.G2Point([sigs1, sigs0], [sigs3, sigs2]);

        if (!Pairing.pairing2(BN256G1.P1(), signature, BN256G1.negate(pubkey), Hm)) revert InvalidBLSSignature();

        recipient.transfer(amount);

    }

}


