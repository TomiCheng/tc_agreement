use alloc::string::String;
use alloc::vec::Vec;
use tc_bigint::PaddedBigUint;

/// A Schnorr zero-knowledge proof {g^v, r = v − x·h mod q} of knowing the x of
/// g^x; Bouncy Castle holds it as an array of two. It is a container alone,
/// checked when received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JPakeZeroKnowledgeProof {
    gv: PaddedBigUint,
    r: PaddedBigUint,
}

impl JPakeZeroKnowledgeProof {
    /// The proof of g^v and r, unchecked. Constant time.
    pub fn new(gv: PaddedBigUint, r: PaddedBigUint) -> Self {
        Self { gv, r }
    }

    /// g^v. Constant time.
    pub fn gv(&self) -> &PaddedBigUint {
        &self.gv
    }

    /// r = v − x·h mod q. Constant time.
    pub fn r(&self) -> &PaddedBigUint {
        &self.r
    }
}

/// Bouncy Castle's `JPakeRound1Payload`: g^x1, g^x2 and their zero-knowledge
/// proofs, sent in the first round. It is a container alone;
/// `JPakeParticipant::validate_round1_payload_received` checks it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JPakeRound1Payload {
    participant_id: String,
    gx1: PaddedBigUint,
    gx2: PaddedBigUint,
    knowledge_proof_for_x1: JPakeZeroKnowledgeProof,
    knowledge_proof_for_x2: JPakeZeroKnowledgeProof,
}

impl JPakeRound1Payload {
    /// The payload of these fields, unchecked. Constant time.
    pub fn new(
        participant_id: &str,
        gx1: PaddedBigUint,
        gx2: PaddedBigUint,
        knowledge_proof_for_x1: JPakeZeroKnowledgeProof,
        knowledge_proof_for_x2: JPakeZeroKnowledgeProof,
    ) -> Self {
        Self {
            participant_id: participant_id.into(),
            gx1,
            gx2,
            knowledge_proof_for_x1,
            knowledge_proof_for_x2,
        }
    }

    /// The sender's participant ID. Constant time.
    pub fn participant_id(&self) -> &str {
        &self.participant_id
    }

    /// g^x1. Constant time.
    pub fn gx1(&self) -> &PaddedBigUint {
        &self.gx1
    }

    /// g^x2. Constant time.
    pub fn gx2(&self) -> &PaddedBigUint {
        &self.gx2
    }

    /// The zero-knowledge proof for x1. Constant time.
    pub fn knowledge_proof_for_x1(&self) -> &JPakeZeroKnowledgeProof {
        &self.knowledge_proof_for_x1
    }

    /// The zero-knowledge proof for x2. Constant time.
    pub fn knowledge_proof_for_x2(&self) -> &JPakeZeroKnowledgeProof {
        &self.knowledge_proof_for_x2
    }
}

/// Bouncy Castle's `JPakeRound2Payload`: A = g^((x1 + x3 + x4)·x2·s) and the
/// zero-knowledge proof for x2·s, sent in the second round. It is a container
/// alone; `JPakeParticipant::validate_round2_payload_received` checks it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JPakeRound2Payload {
    participant_id: String,
    a: PaddedBigUint,
    knowledge_proof_for_x2s: JPakeZeroKnowledgeProof,
}

impl JPakeRound2Payload {
    /// The payload of these fields, unchecked. Constant time.
    pub fn new(
        participant_id: &str,
        a: PaddedBigUint,
        knowledge_proof_for_x2s: JPakeZeroKnowledgeProof,
    ) -> Self {
        Self {
            participant_id: participant_id.into(),
            a,
            knowledge_proof_for_x2s,
        }
    }

    /// The sender's participant ID. Constant time.
    pub fn participant_id(&self) -> &str {
        &self.participant_id
    }

    /// A. Constant time.
    pub fn a(&self) -> &PaddedBigUint {
        &self.a
    }

    /// The zero-knowledge proof for x2·s. Constant time.
    pub fn knowledge_proof_for_x2s(&self) -> &JPakeZeroKnowledgeProof {
        &self.knowledge_proof_for_x2s
    }
}

/// Bouncy Castle's `JPakeRound3Payload`: the MacTag of key confirmation, sent
/// in the third round. Bouncy Castle turns the MacTag into a signed integer;
/// this keeps the MAC's bytes. It is a container alone;
/// `JPakeParticipant::validate_round3_payload_received` checks it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JPakeRound3Payload {
    participant_id: String,
    mac_tag: Vec<u8>,
}

impl JPakeRound3Payload {
    /// The payload of these fields, unchecked. Constant time.
    pub fn new(participant_id: &str, mac_tag: Vec<u8>) -> Self {
        Self {
            participant_id: participant_id.into(),
            mac_tag,
        }
    }

    /// The sender's participant ID. Constant time.
    pub fn participant_id(&self) -> &str {
        &self.participant_id
    }

    /// The MacTag. Constant time.
    pub fn mac_tag(&self) -> &[u8] {
        &self.mac_tag
    }
}
