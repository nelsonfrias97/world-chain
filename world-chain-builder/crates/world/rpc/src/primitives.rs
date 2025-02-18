use alloy_eips::{eip2718::Eip2718Result, Decodable2718, Encodable2718, Typed2718};
use alloy_primitives::{Address, Bytes, TxKind, B256, U256};
use alloy_rlp::{Decodable, Encodable};
use revm_primitives::{AccessList, SignedAuthorization};
use serde::{Deserialize, Serialize};
use world_chain_builder_pbh::PBHSidecar;

pub const PBH_TX_TYPE: u8 = 0x7D;

#[derive(Debug, Deserialize, Serialize)]
pub struct WorldChainTxEnvelope {
    pub(crate) inner: op_alloy_consensus::OpPooledTransaction,
    pub(crate) pbh_sidecar: Option<PBHSidecar>,
}

impl Encodable for WorldChainTxEnvelope {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        self.network_encode(out)
    }

    fn length(&self) -> usize {
        self.network_len()
    }
}

impl Decodable for WorldChainTxEnvelope {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        Ok(Self::network_decode(buf)?)
    }
}

impl Encodable2718 for WorldChainTxEnvelope {
    fn type_flag(&self) -> Option<u8> {
        if self.pbh_sidecar.is_some() {
            Some(PBH_TX_TYPE)
        } else {
            self.inner.type_flag()
        }
    }

    fn encode_2718_len(&self) -> usize {
        self.inner.encode_2718_len()
            + self
                .pbh_sidecar
                .as_ref()
                .map_or(0, |pbh_sidecar| pbh_sidecar.length())
    }

    fn encode_2718(&self, out: &mut dyn alloy_rlp::BufMut) {
        self.inner.encode_2718(out);
        if let Some(sidecar) = &self.pbh_sidecar {
            sidecar.encode(out);
        }
    }

    fn trie_hash(&self) -> B256 {
        self.inner.trie_hash()
    }
}

impl Decodable2718 for WorldChainTxEnvelope {
    fn typed_decode(ty: u8, buf: &mut &[u8]) -> Eip2718Result<Self> {
        if ty == PBH_TX_TYPE {
            // TODO: Figure out how to properly handle OP RLP decoding here
            let inner = op_alloy_consensus::OpPooledTransaction::fallback_decode(buf)?;
            match PBHSidecar::decode(buf) {
                Ok(pbh_sidecar) => Ok(Self {
                    inner,
                    pbh_sidecar: Some(pbh_sidecar),
                }),
                Err(_) => Ok(Self {
                    inner,
                    pbh_sidecar: None,
                }),
            }
        } else {
            let inner = op_alloy_consensus::OpPooledTransaction::typed_decode(ty, buf)?;

            Ok(Self {
                inner,
                pbh_sidecar: None,
            })
        }
    }

    fn fallback_decode(buf: &mut &[u8]) -> Eip2718Result<Self> {
        let inner = op_alloy_consensus::OpPooledTransaction::fallback_decode(buf)?;

        Ok(Self {
            inner,
            pbh_sidecar: None,
        })
    }
}

impl Typed2718 for WorldChainTxEnvelope {
    fn ty(&self) -> u8 {
        if self.pbh_sidecar.is_some() {
            PBH_TX_TYPE
        } else {
            self.inner.ty()
        }
    }
}

impl alloy_consensus::Transaction for WorldChainTxEnvelope {
    fn chain_id(&self) -> Option<u64> {
        self.inner.chain_id()
    }

    fn nonce(&self) -> u64 {
        self.inner.nonce()
    }

    fn gas_limit(&self) -> u64 {
        self.inner.gas_limit()
    }

    fn gas_price(&self) -> Option<u128> {
        self.inner.gas_price()
    }

    fn max_fee_per_gas(&self) -> u128 {
        self.inner.max_fee_per_gas()
    }

    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        self.inner.max_priority_fee_per_gas()
    }

    fn max_fee_per_blob_gas(&self) -> Option<u128> {
        self.inner.max_fee_per_blob_gas()
    }

    fn priority_fee_or_price(&self) -> u128 {
        self.inner.priority_fee_or_price()
    }

    fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
        self.inner.effective_gas_price(base_fee)
    }

    fn is_dynamic_fee(&self) -> bool {
        self.inner.is_dynamic_fee()
    }

    fn kind(&self) -> TxKind {
        self.inner.kind()
    }

    fn is_create(&self) -> bool {
        self.inner.is_create()
    }

    fn to(&self) -> Option<Address> {
        self.inner.to()
    }

    fn value(&self) -> U256 {
        self.inner.value()
    }

    fn input(&self) -> &Bytes {
        self.inner.input()
    }

    fn access_list(&self) -> Option<&AccessList> {
        self.inner.access_list()
    }

    fn blob_versioned_hashes(&self) -> Option<&[B256]> {
        self.inner.blob_versioned_hashes()
    }

    fn authorization_list(&self) -> Option<&[SignedAuthorization]> {
        self.inner.authorization_list()
    }
}

#[cfg(test)]
mod tests {
    // TODO: Round trip tests
}
