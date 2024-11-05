use anyhow::Context;
use prost::Message;
use std::str::FromStr;

use ibc::clients::tendermint::client_state::ClientState as TmClientState;
use ibc::clients::tendermint::consensus_state::ConsensusState as TmConsensusState;
use ibc::clients::tendermint::types::{
    ClientState as ClientStateType, ConsensusState as ConsensusStateType,
};

#[derive(ibc::derive::ClientState)]
#[validation(Ibc)]
#[execution(Ibc)]
pub enum AnyClientState {
    Tendermint(TmClientState),
}

impl From<ClientStateType> for AnyClientState {
    fn from(value: ClientStateType) -> Self {
        Self::Tendermint(value.into())
    }
}

impl From<AnyClientState> for ibc::primitives::proto::Any {
    fn from(value: AnyClientState) -> Self {
        match value {
            AnyClientState::Tendermint(v) => v.into(),
        }
    }
}

impl TryFrom<ibc::primitives::proto::Any> for AnyClientState {
    type Error = ibc::core::host::types::error::DecodingError;

    fn try_from(value: ibc::primitives::proto::Any) -> Result<Self, Self::Error> {
        if value.type_url == ibc::clients::tendermint::types::TENDERMINT_CLIENT_STATE_TYPE_URL {
            Ok(Self::Tendermint(value.try_into()?))
        } else {
            Err(ibc::core::host::types::error::DecodingError::UnknownTypeUrl(value.type_url))
        }
    }
}

#[derive(ibc::derive::ConsensusState)]
pub enum AnyConsensusState {
    Tendermint(TmConsensusState),
}

impl From<ConsensusStateType> for AnyConsensusState {
    fn from(value: ConsensusStateType) -> Self {
        Self::Tendermint(value.into())
    }
}

impl From<AnyConsensusState> for ibc::primitives::proto::Any {
    fn from(value: AnyConsensusState) -> Self {
        match value {
            AnyConsensusState::Tendermint(v) => v.into(),
        }
    }
}

impl TryFrom<ibc::primitives::proto::Any> for AnyConsensusState {
    type Error = ibc::core::host::types::error::DecodingError;

    fn try_from(value: ibc::primitives::proto::Any) -> Result<Self, Self::Error> {
        if value.type_url == ibc::clients::tendermint::types::TENDERMINT_CONSENSUS_STATE_TYPE_URL {
            Ok(Self::Tendermint(value.try_into()?))
        } else {
            Err(ibc::core::host::types::error::DecodingError::UnknownTypeUrl(value.type_url))
        }
    }
}

impl TryFrom<AnyConsensusState> for ibc::clients::tendermint::types::ConsensusState {
    type Error = ibc::core::host::types::error::DecodingError;

    fn try_from(value: AnyConsensusState) -> Result<Self, Self::Error> {
        match value {
            AnyConsensusState::Tendermint(c) => Ok(c.inner().clone()),
        }
    }
}

pub struct Ibc {
    pub chain_id: ibc::core::host::types::identifiers::ChainId,
    pub grpc_addr: String,
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

impl ibc::core::host::ValidationContext for Ibc {
    type V = Self;
    type HostClientState = TmClientState;
    type HostConsensusState = TmConsensusState;

    fn get_client_validation_context(&self) -> &Self::V {
        unimplemented!()
    }
    fn host_timestamp(
        &self,
    ) -> Result<ibc::core::primitives::Timestamp, ibc::core::host::types::error::HostError> {
        unimplemented!()
    }
    fn host_consensus_state(
        &self,
        _height: &ibc::core::client::types::Height,
    ) -> Result<Self::HostConsensusState, ibc::core::host::types::error::HostError> {
        unimplemented!()
    }
    fn client_counter(&self) -> Result<u64, ibc::core::host::types::error::HostError> {
        unimplemented!()
    }
    fn connection_end(
        &self,
        _conn_id: &ibc::core::host::types::identifiers::ConnectionId,
    ) -> Result<ibc::core::connection::types::ConnectionEnd, ibc::core::host::types::error::HostError>
    {
        unimplemented!()
    }
    fn validate_self_client(
        &self,
        _client_state_of_host_on_counterparty: Self::HostClientState,
    ) -> Result<(), ibc::core::host::types::error::HostError> {
        unimplemented!()
    }
    fn commitment_prefix(&self) -> ibc::core::commitment_types::commitment::CommitmentPrefix {
        unimplemented!()
    }
    fn connection_counter(&self) -> Result<u64, ibc::core::host::types::error::HostError> {
        unimplemented!()
    }
    fn channel_end(
        &self,
        _channel_end_path: &ibc::core::host::types::path::ChannelEndPath,
    ) -> Result<
        ibc::core::channel::types::channel::ChannelEnd,
        ibc::core::host::types::error::HostError,
    > {
        unimplemented!()
    }
    fn get_next_sequence_send(
        &self,
        _seq_send_path: &ibc::core::host::types::path::SeqSendPath,
    ) -> Result<
        ibc::core::host::types::identifiers::Sequence,
        ibc::core::host::types::error::HostError,
    > {
        unimplemented!()
    }
    fn get_next_sequence_recv(
        &self,
        _seq_recv_path: &ibc::core::host::types::path::SeqRecvPath,
    ) -> Result<
        ibc::core::host::types::identifiers::Sequence,
        ibc::core::host::types::error::HostError,
    > {
        unimplemented!()
    }
    fn get_next_sequence_ack(
        &self,
        _seq_ack_path: &ibc::core::host::types::path::SeqAckPath,
    ) -> Result<
        ibc::core::host::types::identifiers::Sequence,
        ibc::core::host::types::error::HostError,
    > {
        unimplemented!()
    }
    fn get_packet_commitment(
        &self,
        _commitment_path: &ibc::core::host::types::path::CommitmentPath,
    ) -> Result<
        ibc::core::channel::types::commitment::PacketCommitment,
        ibc::core::host::types::error::HostError,
    > {
        unimplemented!()
    }
    fn get_packet_receipt(
        &self,
        _receipt_path: &ibc::core::host::types::path::ReceiptPath,
    ) -> Result<ibc::core::channel::types::packet::Receipt, ibc::core::host::types::error::HostError>
    {
        unimplemented!()
    }
    fn get_packet_acknowledgement(
        &self,
        _ack_path: &ibc::core::host::types::path::AckPath,
    ) -> Result<
        ibc::core::channel::types::commitment::AcknowledgementCommitment,
        ibc::core::host::types::error::HostError,
    > {
        unimplemented!()
    }
    fn channel_counter(&self) -> Result<u64, ibc::core::host::types::error::HostError> {
        unimplemented!()
    }
    fn max_expected_time_per_block(&self) -> std::time::Duration {
        unimplemented!()
    }
    fn validate_message_signer(
        &self,
        _signer: &ibc::core::primitives::Signer,
    ) -> Result<(), ibc::core::host::types::error::HostError> {
        unimplemented!()
    }
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
    fn get_height(block: &tendermint_proto::v0_38::types::Block) -> Option<i64> {
        Some(block.header.as_ref()?.height)
    }
    use cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::{
        service_client::ServiceClient, GetLatestBlockRequest,
    };
    ServiceClient::connect(grpc_addr.to_string())
        .await?
        .get_latest_block(GetLatestBlockRequest {})
        .await?
        .get_ref()
        .block
        .as_ref()
        .and_then(get_height)
        .context("no height")
}

impl ibc::core::client::context::ClientValidationContext for Ibc {
    type ClientStateRef = AnyClientState;
    type ConsensusStateRef = AnyConsensusState;

    fn client_state(
        &self,
        _client_id: &ibc::core::host::types::identifiers::ClientId,
    ) -> Result<Self::ClientStateRef, ibc::core::host::types::error::HostError> {
        unimplemented!()
    }
    fn consensus_state(
        &self,
        _client_cons_state_path: &ibc::core::host::types::path::ClientConsensusStatePath,
    ) -> Result<Self::ConsensusStateRef, ibc::core::host::types::error::HostError> {
        unimplemented!()
    }
    fn client_update_meta(
        &self,
        _client_id: &ibc::core::host::types::identifiers::ClientId,
        _height: &ibc::core::client::types::Height,
    ) -> Result<
        (
            ibc::core::primitives::Timestamp,
            ibc::core::client::types::Height,
        ),
        ibc::core::host::types::error::HostError,
    > {
        unimplemented!()
    }
}

impl ibc::core::client::context::ClientExecutionContext for Ibc {
    type ClientStateMut = AnyClientState;

    fn store_client_state(
        &mut self,
        _client_state_path: ibc::core::host::types::path::ClientStatePath,
        _client_state: Self::ClientStateRef,
    ) -> Result<(), ibc::core::host::types::error::HostError> {
        unimplemented!()
    }
    fn store_consensus_state(
        &mut self,
        _consensus_state_path: ibc::core::host::types::path::ClientConsensusStatePath,
        _consensus_state: Self::ConsensusStateRef,
    ) -> Result<(), ibc::core::host::types::error::HostError> {
        unimplemented!()
    }
    fn delete_consensus_state(
        &mut self,
        _consensus_state_path: ibc::core::host::types::path::ClientConsensusStatePath,
    ) -> Result<(), ibc::core::host::types::error::HostError> {
        unimplemented!()
    }
    fn store_update_meta(
        &mut self,
        _client_id: ibc::core::host::types::identifiers::ClientId,
        _height: ibc::core::client::types::Height,
        _host_timestamp: ibc::core::primitives::Timestamp,
        _host_height: ibc::core::client::types::Height,
    ) -> Result<(), ibc::core::host::types::error::HostError> {
        unimplemented!()
    }
    fn delete_update_meta(
        &mut self,
        _client_id: ibc::core::host::types::identifiers::ClientId,
        _height: ibc::core::client::types::Height,
    ) -> Result<(), ibc::core::host::types::error::HostError> {
        unimplemented!()
    }
}

impl ibc::core::client::context::ExtClientValidationContext for Ibc {
    fn host_timestamp(
        &self,
    ) -> Result<ibc::core::primitives::Timestamp, ibc::core::host::types::error::HostError> {
        unimplemented!()
    }
    fn host_height(
        &self,
    ) -> Result<ibc::core::client::types::Height, ibc::core::host::types::error::HostError> {
        unimplemented!()
    }
    fn consensus_state_heights(
        &self,
        _client_id: &ibc::core::host::types::identifiers::ClientId,
    ) -> Result<Vec<ibc::core::client::types::Height>, ibc::core::host::types::error::HostError>
    {
        unimplemented!()
    }
    fn next_consensus_state(
        &self,
        _client_id: &ibc::core::host::types::identifiers::ClientId,
        _height: &ibc::core::client::types::Height,
    ) -> Result<Option<Self::ConsensusStateRef>, ibc::core::host::types::error::HostError> {
        unimplemented!()
    }
    fn prev_consensus_state(
        &self,
        _client_id: &ibc::core::host::types::identifiers::ClientId,
        _height: &ibc::core::client::types::Height,
    ) -> Result<Option<Self::ConsensusStateRef>, ibc::core::host::types::error::HostError> {
        unimplemented!()
    }
}

impl ibc_query::core::context::QueryContext for Ibc {
    fn client_states(
        &self,
    ) -> Result<
        Vec<(
            ibc::core::host::types::identifiers::ClientId,
            ibc::core::host::ClientStateRef<Self>,
        )>,
        ibc::core::host::types::error::HostError,
    > {
        unimplemented!()
    }
    fn consensus_states(
        &self,
        _client_id: &ibc::core::host::types::identifiers::ClientId,
    ) -> Result<
        Vec<(
            ibc::core::client::types::Height,
            ibc::core::host::ConsensusStateRef<Self>,
        )>,
        ibc::core::host::types::error::HostError,
    > {
        unimplemented!()
    }
    fn consensus_state_heights(
        &self,
        _client_id: &ibc::core::host::types::identifiers::ClientId,
    ) -> Result<Vec<ibc::core::client::types::Height>, ibc::core::host::types::error::HostError>
    {
        unimplemented!()
    }
    fn connection_ends(
        &self,
    ) -> Result<
        Vec<ibc::core::connection::types::IdentifiedConnectionEnd>,
        ibc::core::host::types::error::HostError,
    > {
        unimplemented!()
    }
    fn client_connection_ends(
        &self,
        _client_id: &ibc::core::host::types::identifiers::ClientId,
    ) -> Result<
        Vec<ibc::core::host::types::identifiers::ConnectionId>,
        ibc::core::host::types::error::HostError,
    > {
        unimplemented!()
    }
    fn channel_ends(
        &self,
    ) -> Result<
        Vec<ibc::core::channel::types::channel::IdentifiedChannelEnd>,
        ibc::core::host::types::error::HostError,
    > {
        unimplemented!()
    }
    fn packet_acknowledgements(
        &self,
        _channel_end_path: &ibc::core::host::types::path::ChannelEndPath,
        _sequences: impl ExactSizeIterator<Item = ibc::core::host::types::identifiers::Sequence>,
    ) -> Result<
        Vec<ibc::core::channel::types::packet::PacketState>,
        ibc::core::host::types::error::HostError,
    > {
        unimplemented!()
    }
    fn unreceived_packets(
        &self,
        _channel_end_path: &ibc::core::host::types::path::ChannelEndPath,
        _sequences: impl ExactSizeIterator<Item = ibc::core::host::types::identifiers::Sequence>,
    ) -> Result<
        Vec<ibc::core::host::types::identifiers::Sequence>,
        ibc::core::host::types::error::HostError,
    > {
        unimplemented!()
    }
    fn unreceived_acks(
        &self,
        _channel_end_path: &ibc::core::host::types::path::ChannelEndPath,
        _sequences: impl ExactSizeIterator<Item = ibc::core::host::types::identifiers::Sequence>,
    ) -> Result<
        Vec<ibc::core::host::types::identifiers::Sequence>,
        ibc::core::host::types::error::HostError,
    > {
        unimplemented!()
    }
    fn packet_commitments(
        &self,
        channel_end_path: &ibc::core::host::types::path::ChannelEndPath,
    ) -> Result<
        Vec<ibc::core::channel::types::packet::PacketState>,
        ibc::core::host::types::error::HostError,
    > {
        fn get_commitments(
            commitments: anyhow::Result<Vec<ibc_proto::ibc::core::channel::v1::PacketState>>,
        ) -> anyhow::Result<Vec<ibc::core::channel::types::packet::PacketState>> {
            let mut v: Vec<ibc::core::channel::types::packet::PacketState> = Vec::new();
            for c in commitments? {
                v.push(ibc::core::channel::types::packet::PacketState {
                    port_id: ibc::core::host::types::identifiers::PortId::new(c.port_id.clone())?,
                    chan_id: ibc::core::host::types::identifiers::ChannelId::from_str(
                        &c.channel_id,
                    )?,
                    seq: ibc::core::host::types::identifiers::Sequence::from(c.sequence),
                    data: c.data.clone(),
                })
            }
            Ok(v)
        }
        let rt = tokio::runtime::Runtime::new().unwrap();
        let commitments = rt.block_on(async {
            packet_commitments(
                &self.grpc_addr,
                channel_end_path.0.as_str(),
                channel_end_path.1.as_str(),
            )
            .await
        });
        get_commitments(commitments)
            .map_err(ibc::core::host::types::error::HostError::invalid_state)
    }
}

fn default_page_request() -> ibc_proto::cosmos::base::query::v1beta1::PageRequest {
    ibc_proto::cosmos::base::query::v1beta1::PageRequest {
        count_total: false,
        key: b"".to_vec(),
        limit: 1000,
        offset: 0,
        reverse: false,
    }
}

async fn packet_commitments(
    grpc_addr: &str,
    port_id: &str,
    channel_id: &str,
) -> anyhow::Result<Vec<ibc_proto::ibc::core::channel::v1::PacketState>> {
    let mut pagination = Some(default_page_request());
    let mut commitments: Vec<ibc_proto::ibc::core::channel::v1::PacketState> = Vec::new();
    loop {
        let response = ibc_proto::ibc::core::channel::v1::query_client::QueryClient::connect(
            grpc_addr.to_string(),
        )
        .await?
        .packet_commitments(
            ibc_proto::ibc::core::channel::v1::QueryPacketCommitmentsRequest {
                port_id: port_id.to_string(),
                channel_id: channel_id.to_string(),
                pagination: pagination.clone(),
            },
        )
        .await?;
        commitments.extend(response.get_ref().commitments.clone());
        let next_key = response
            .get_ref()
            .pagination
            .as_ref()
            .map(|v| v.next_key.clone());
        if let Some(next_key) = next_key {
            if next_key.is_empty() {
                break;
            }
            if let Some(pagination) = &mut pagination {
                pagination.key = next_key;
            }
        } else {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    Ok(commitments)
}
