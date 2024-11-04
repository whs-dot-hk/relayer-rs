use anyhow::Context;
use prost::Message;

pub struct Ibc {
    chain_id: ibc::core::host::types::identifiers::ChainId,
    grpc_addr: String,
}

impl ibc_query::core::context::ProvableContext for Ibc {
    fn get_proof(
        &self,
        height: ibc::core::client::types::Height,
        path: &ibc::core::host::types::path::Path,
    ) -> Option<Vec<u8>> {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async { abci_query(&self.grpc_addr, height, path).await.ok() })
    }
}

async fn abci_query(
    grpc_addr: &str,
    height: ibc::core::client::types::Height,
    path: &ibc::core::host::types::path::Path,
) -> anyhow::Result<Vec<u8>> {
    let response =
        ibc_proto::cosmos::base::tendermint::v1beta1::service_client::ServiceClient::connect(
            grpc_addr.to_string(),
        )
        .await?
        .abci_query(
            ibc_proto::cosmos::base::tendermint::v1beta1::AbciQueryRequest {
                data: path.clone().into_bytes(),
                path: ibc::cosmos_host::IBC_QUERY_PATH.to_string(),
                height: height.revision_height().try_into()?,
                prove: true,
            },
        )
        .await?;
    Ok(get_merkle_proof(response.get_ref().proof_ops.as_ref())?.encode_to_vec())
}

fn get_merkle_proof(
    proof_ops: Option<&ibc_proto::cosmos::base::tendermint::v1beta1::ProofOps>,
) -> anyhow::Result<ibc_proto::ibc::core::commitment::v1::MerkleProof> {
    let proof_ops: Vec<ibc_proto::cosmos::base::tendermint::v1beta1::ProofOp> = proof_ops
        .cloned()
        .map(|p| p.ops)
        .into_iter()
        .flatten()
        .collect();
    let mut proofs: Vec<ics23::CommitmentProof> = Vec::new();
    for proof_op in proof_ops {
        proofs.push(ics23::CommitmentProof::decode(bytes::Bytes::from(
            proof_op.data.clone(),
        ))?);
    }
    Ok(ibc_proto::ibc::core::commitment::v1::MerkleProof { proofs })
}

impl Ibc {
    fn host_height(
        &self,
    ) -> Result<ibc::core::client::types::Height, ibc::core::host::types::error::HostError> {
        fn get_height(
            chain_id: &ibc::core::host::types::identifiers::ChainId,
            height: anyhow::Result<i64>,
        ) -> anyhow::Result<ibc::core::client::types::Height> {
            Ok(ibc::core::client::types::Height::new(
                chain_id.revision_number(),
                height?.try_into()?,
            )?)
        }
        let rt = tokio::runtime::Runtime::new().unwrap();
        let height = rt.block_on(async { get_latest_block(&self.grpc_addr).await });
        get_height(&self.chain_id, height)
            .map_err(ibc::core::host::types::error::HostError::invalid_state)
    }
}

async fn get_latest_block(grpc_addr: &str) -> anyhow::Result<i64> {
    fn get_height(block: Option<&tendermint_proto::v0_38::types::Block>) -> Option<i64> {
        Some(block?.header.as_ref()?.height)
    }
    use cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::{
        service_client::ServiceClient, GetLatestBlockRequest,
    };
    let response = ServiceClient::connect(grpc_addr.to_string())
        .await?
        .get_latest_block(GetLatestBlockRequest {})
        .await?;
    get_height(response.get_ref().block.as_ref()).context("no height")
}
