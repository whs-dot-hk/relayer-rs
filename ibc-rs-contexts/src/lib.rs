use anyhow::Context;
use prost::Message;

pub struct Ibc {
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
                height: height
                    .revision_height()
                    .try_into()
                    .context("no revision height")?,
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
