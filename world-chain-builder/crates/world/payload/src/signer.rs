use alloy_signer::{Signature, Signer};
use alloy_signer_aws::AwsSigner;
use alloy_signer_local::PrivateKeySigner;
use revm_primitives::B256;

#[derive(Debug, Clone)]
pub enum PbhSigner {
    Local(PrivateKeySigner),
    Aws(AwsSigner),
}

impl PbhSigner {
    pub async fn sign_hash(&self, hash: &B256) -> Result<Signature, alloy_signer::Error> {
        match self {
            PbhSigner::Local(signer) => signer.sign_hash(hash).await,
            PbhSigner::Aws(signer) => signer.sign_hash(hash).await,
        }
    }
}
