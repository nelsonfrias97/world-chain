use std::fmt::Display;
use std::sync::Arc;

use alloy_consensus::{proofs, Eip658Value, EMPTY_OMMER_ROOT_HASH};
use alloy_eips::eip4895::Withdrawals;
use alloy_eips::merge::BEACON_NONCE;
use alloy_rlp::Encodable;
use alloy_rpc_types_debug::ExecutionWitness;
use op_alloy_consensus::{OpDepositReceipt, OpTxType};
use reth::api::PayloadBuilderError;
use reth::payload::{PayloadBuilderAttributes, PayloadId};
use reth::revm::database::StateProviderDatabase;
use reth::revm::db::states::bundle_state::BundleRetention;
use reth::revm::witness::ExecutionWitnessRecord;
use reth::revm::{DatabaseCommit, State};
use reth::transaction_pool::{BestTransactionsAttributes, TransactionPool};
use reth_basic_payload_builder::{
    is_better_payload, BuildArguments, BuildOutcome, BuildOutcomeKind, MissingPayloadBehaviour,
    PayloadBuilder, PayloadConfig,
};
use reth_chain_state::ExecutedBlock;
use reth_evm::env::EvmEnv;
use reth_evm::{ConfigureEvm, Evm};
use reth_optimism_chainspec::OpChainSpec;
use reth_optimism_consensus::calculate_receipt_root_no_memo_optimism;
use reth_optimism_node::{OpBuiltPayload, OpPayloadBuilder, OpPayloadBuilderAttributes};
use reth_optimism_payload_builder::builder::{
    ExecutedPayload, ExecutionInfo, OpPayloadBuilderCtx, OpPayloadTransactions,
};
use reth_optimism_payload_builder::config::OpBuilderConfig;
use reth_optimism_payload_builder::OpPayloadAttributes;
use reth_optimism_primitives::{OpPrimitives, OpReceipt, OpTransactionSigned};
use reth_primitives::{
    Block, BlockBody, Header, InvalidTransactionError, RecoveredBlock, SealedHeader,
};
use reth_primitives_traits::Block as _;
use reth_provider::{
    BlockReaderIdExt, ChainSpecProvider, ExecutionOutcome, HashedPostStateProvider, ProviderError,
    StateProofProvider, StateProviderFactory, StateRootProvider,
};
use reth_transaction_pool::error::InvalidPoolTransactionError;
use reth_transaction_pool::{BestTransactions, ValidPoolTransaction};
use revm::{Database, EvmBuilder};
use revm_primitives::{Bytes, EVMError, InvalidTransaction, ResultAndState, B256, U256};
use tracing::{debug, trace, warn};
use world_chain_builder_pool::noop::NoopWorldChainTransactionPool;
use world_chain_builder_pool::tx::{WorldChainPoolTransaction, WorldChainPoolTransactionError};
use world_chain_builder_rpc::transactions::validate_conditional_options;

use crate::inspector::PBHCallTracer;

/// World Chain payload builder
#[derive(Debug, Clone)]
pub struct WorldChainPayloadBuilder<EvmConfig, Tx = ()> {
    pub inner: OpPayloadBuilder<EvmConfig, Tx>,
    pub verified_blockspace_capacity: u8,
}

impl<EvmConfig> WorldChainPayloadBuilder<EvmConfig>
where
    EvmConfig: ConfigureEvm<Header = Header>,
{
    pub fn new(evm_config: EvmConfig, verified_blockspace_capacity: u8) -> Self {
        Self::with_builder_config(evm_config, Default::default(), verified_blockspace_capacity)
    }

    pub const fn with_builder_config(
        evm_config: EvmConfig,
        builder_config: OpBuilderConfig,
        verified_blockspace_capacity: u8,
    ) -> Self {
        let inner = OpPayloadBuilder::with_builder_config(evm_config, builder_config);

        Self {
            inner,
            verified_blockspace_capacity,
        }
    }
}

impl<EvmConfig, Tx> WorldChainPayloadBuilder<EvmConfig, Tx> {
    /// Sets the rollup's compute pending block configuration option.
    pub const fn set_compute_pending_block(mut self, compute_pending_block: bool) -> Self {
        self.inner.compute_pending_block = compute_pending_block;
        self
    }

    pub fn with_transactions<T: OpPayloadTransactions>(
        self,
        best_transactions: T,
    ) -> WorldChainPayloadBuilder<EvmConfig, T> {
        let Self {
            inner,
            verified_blockspace_capacity,
        } = self;

        let OpPayloadBuilder {
            compute_pending_block,
            evm_config,
            config,
            ..
        } = inner;

        WorldChainPayloadBuilder {
            inner: OpPayloadBuilder {
                compute_pending_block,
                evm_config,
                best_transactions,
                config,
            },
            verified_blockspace_capacity,
        }
    }

    /// Enables the rollup's compute pending block configuration option.
    pub const fn compute_pending_block(self) -> Self {
        self.set_compute_pending_block(true)
    }

    /// Returns the rollup's compute pending block configuration option.
    pub const fn is_compute_pending_block(&self) -> bool {
        self.inner.compute_pending_block
    }
}

impl<EvmConfig, Txs> WorldChainPayloadBuilder<EvmConfig, Txs>
where
    EvmConfig: ConfigureEvm<Header = Header, Transaction = OpTransactionSigned>,
    Txs: OpPayloadTransactions,
{
    /// Constructs an Optimism payload from the transactions sent via the
    /// Payload attributes by the sequencer. If the `no_tx_pool` argument is passed in
    /// the payload attributes, the transaction pool will be ignored and the only transactions
    /// included in the payload will be those sent through the attributes.
    ///
    /// Given build arguments including an Optimism client, transaction pool,
    /// and configuration, this function creates a transaction payload. Returns
    /// a result indicating success with the payload or an error in case of failure.
    fn build_payload<Client, Pool>(
        &self,
        args: BuildArguments<Pool, Client, OpPayloadBuilderAttributes, OpBuiltPayload>,
    ) -> Result<BuildOutcome<OpBuiltPayload>, PayloadBuilderError>
    where
        Client:
            StateProviderFactory + ChainSpecProvider<ChainSpec = OpChainSpec> + BlockReaderIdExt,
        Pool: TransactionPool<
            Transaction: WorldChainPoolTransaction<Consensus = OpTransactionSigned>,
        >,
    {
        let evm_env = self
            .cfg_and_block_env(&args.config.attributes, &args.config.parent_header)
            .map_err(PayloadBuilderError::other)?;

        let BuildArguments {
            client,
            pool,
            mut cached_reads,
            config,
            cancel,
            best_payload,
        } = args;

        let ctx = WorldChainPayloadBuilderCtx {
            inner: OpPayloadBuilderCtx {
                evm_config: self.inner.evm_config.clone(),
                da_config: self.inner.config.da_config.clone(),
                chain_spec: client.chain_spec(),
                config,
                evm_env,
                cancel,
                best_payload,
            },
            verified_blockspace_capacity: self.verified_blockspace_capacity,
            client,
        };

        let builder = WorldChainBuilder {
            pool,
            _best: self.inner.best_transactions.clone(),
        };

        let client = ctx.client();
        let state_provider = client.state_by_block_hash(ctx.parent().hash())?;
        let state = StateProviderDatabase::new(state_provider);

        let build_outcome = if ctx.attributes().no_tx_pool {
            let db = State::builder()
                .with_database(state)
                .with_bundle_update()
                .build();

            builder.build(db, ctx)?
        } else {
            // sequencer mode we can reuse cachedreads from previous runs
            let db = State::builder()
                .with_database(cached_reads.as_db_mut(state))
                .with_bundle_update()
                .build();

            builder.build(db, ctx)?
        };

        Ok(build_outcome.with_cached_reads(cached_reads))
    }

    /// Returns the configured [`EvmEnv`] for the targeted payload
    /// (that has the `parent` as its parent).
    pub fn cfg_and_block_env(
        &self,
        attributes: &OpPayloadBuilderAttributes,
        parent: &Header,
    ) -> Result<EvmEnv, EvmConfig::Error> {
        self.inner.cfg_and_block_env(attributes, parent)
    }

    /// Computes the witness for the payload.
    pub fn payload_witness<Client>(
        &self,
        client: Client,
        parent: SealedHeader,
        attributes: OpPayloadAttributes,
    ) -> Result<ExecutionWitness, PayloadBuilderError>
    where
        Client:
            StateProviderFactory + ChainSpecProvider<ChainSpec = OpChainSpec> + BlockReaderIdExt,
    {
        let attributes = OpPayloadBuilderAttributes::try_new(parent.hash(), attributes, 3)
            .map_err(PayloadBuilderError::other)?;

        let evm_env = self
            .cfg_and_block_env(&attributes, &parent)
            .map_err(PayloadBuilderError::other)?;

        let config = PayloadConfig {
            parent_header: Arc::new(parent),
            attributes,
        };
        let ctx = WorldChainPayloadBuilderCtx {
            inner: OpPayloadBuilderCtx {
                evm_config: self.inner.evm_config.clone(),
                da_config: self.inner.config.da_config.clone(),
                chain_spec: client.chain_spec(),
                config,
                evm_env,
                cancel: Default::default(),
                best_payload: Default::default(),
            },
            verified_blockspace_capacity: self.verified_blockspace_capacity,
            client,
        };

        let client = ctx.client();
        let state_provider = client.state_by_block_hash(ctx.parent().hash())?;
        let state = StateProviderDatabase::new(state_provider);
        let mut state = State::builder()
            .with_database(state)
            .with_bundle_update()
            .build();

        let builder = WorldChainBuilder {
            pool: NoopWorldChainTransactionPool::default(),
            _best: (),
        };
        builder.witness(&mut state, &ctx)
    }
}

/// Implementation of the [`PayloadBuilder`] trait for [`WorldChainPayloadBuilder`].
impl<Pool, Client, EvmConfig, Txs> PayloadBuilder<Pool, Client>
    for WorldChainPayloadBuilder<EvmConfig, Txs>
where
    Client: StateProviderFactory
        + ChainSpecProvider<ChainSpec = OpChainSpec>
        + BlockReaderIdExt
        + Clone,
    Pool: TransactionPool<Transaction: WorldChainPoolTransaction<Consensus = OpTransactionSigned>>,
    EvmConfig: ConfigureEvm<Header = Header, Transaction = OpTransactionSigned>,
    Txs: OpPayloadTransactions,
{
    type Attributes = OpPayloadBuilderAttributes;
    type BuiltPayload = OpBuiltPayload;

    fn try_build(
        &self,
        args: BuildArguments<Pool, Client, OpPayloadBuilderAttributes, OpBuiltPayload>,
    ) -> Result<BuildOutcome<OpBuiltPayload>, PayloadBuilderError> {
        self.build_payload(args)
    }

    fn on_missing_payload(
        &self,
        _args: BuildArguments<Pool, Client, OpPayloadBuilderAttributes, OpBuiltPayload>,
    ) -> MissingPayloadBehaviour<Self::BuiltPayload> {
        // we want to await the job that's already in progress because that should be returned as
        // is, there's no benefit in racing another job
        MissingPayloadBehaviour::AwaitInProgress
    }

    // NOTE: this should only be used for testing purposes because this doesn't have access to L1
    // system txs, hence on_missing_payload we return [MissingPayloadBehaviour::AwaitInProgress].
    fn build_empty_payload(
        &self,
        client: &Client,
        config: PayloadConfig<Self::Attributes>,
    ) -> Result<OpBuiltPayload, PayloadBuilderError> {
        let args = BuildArguments {
            client: client.clone(),
            config,
            pool: NoopWorldChainTransactionPool::default(),
            cached_reads: Default::default(),
            cancel: Default::default(),
            best_payload: None,
        };
        self.build_payload(args)?
            .into_payload()
            .ok_or_else(|| PayloadBuilderError::MissingPayload)
    }
}

/// The type that builds the payload.
///
/// Payload building for optimism is composed of several steps.
/// The first steps are mandatory and defined by the protocol.
///
/// 1. first all System calls are applied.
/// 2. After canyon the forced deployed `create2deployer` must be loaded
/// 3. all sequencer transactions are executed (part of the payload attributes)
///
/// Depending on whether the node acts as a sequencer and is allowed to include additional
/// transactions (`no_tx_pool == false`):
/// 4. include additional transactions
///
/// And finally
/// 5. build the block: compute all roots (txs, state)
#[derive(Debug)]
pub struct WorldChainBuilder<Pool, Txs> {
    /// The transaction pool
    pool: Pool,
    /// Yields the best transaction to include if transactions from the mempool are allowed.
    _best: Txs,
}

impl<Pool, Txs> WorldChainBuilder<Pool, Txs>
where
    Pool: TransactionPool<Transaction: WorldChainPoolTransaction<Consensus = OpTransactionSigned>>,
    Txs: OpPayloadTransactions,
{
    /// Executes the payload and returns the outcome.
    pub fn execute<EvmConfig, DB, Client>(
        self,
        state: &mut State<DB>,
        ctx: &WorldChainPayloadBuilderCtx<EvmConfig, Client>,
    ) -> Result<BuildOutcomeKind<ExecutedPayload>, PayloadBuilderError>
    where
        EvmConfig: ConfigureEvm<Header = Header, Transaction = OpTransactionSigned>,
        DB: Database<Error = ProviderError>,
        Client:
            StateProviderFactory + ChainSpecProvider<ChainSpec = OpChainSpec> + BlockReaderIdExt,
    {
        let Self { pool, _best } = self;
        debug!(target: "payload_builder", id=%ctx.payload_id(), parent_header = ?ctx.parent().hash(), parent_number = ctx.parent().number, "building new payload");

        // 1. apply eip-4788 pre block contract call
        ctx.apply_pre_beacon_root_contract_call(state)?;

        // 2. ensure create2deployer is force deployed
        ctx.ensure_create2_deployer(state)?;

        // 3. execute sequencer transactions
        let mut info = ctx.execute_sequencer_transactions(state)?;

        // 4. if mem pool transactions are requested we execute them
        if !ctx.attributes().no_tx_pool {
            //TODO: build pbh payload
            let best_txs =
                pool.best_transactions_with_attributes(ctx.best_transaction_attributes());

            if ctx
                .execute_best_transactions::<_, Pool>(&mut info, state, &pool, best_txs)?
                .is_some()
            {
                return Ok(BuildOutcomeKind::Cancelled);
            }

            // check if the new payload is even more valuable
            if !ctx.is_better_payload(info.total_fees) {
                // can skip building the block
                return Ok(BuildOutcomeKind::Aborted {
                    fees: info.total_fees,
                });
            }
        }

        let withdrawals_root = ctx.commit_withdrawals(state)?;

        // merge all transitions into bundle state, this would apply the withdrawal balance changes
        // and 4788 contract call
        state.merge_transitions(BundleRetention::Reverts);

        Ok(BuildOutcomeKind::Better {
            payload: ExecutedPayload {
                info,
                withdrawals_root,
            },
        })
    }

    /// Builds the payload on top of the state.
    pub fn build<EvmConfig, DB, P, Client>(
        self,
        mut state: State<DB>,
        ctx: WorldChainPayloadBuilderCtx<EvmConfig, Client>,
    ) -> Result<BuildOutcomeKind<OpBuiltPayload>, PayloadBuilderError>
    where
        EvmConfig: ConfigureEvm<Header = Header, Transaction = OpTransactionSigned>,
        DB: Database<Error = ProviderError> + AsRef<P>,
        P: StateRootProvider + HashedPostStateProvider,
        Client:
            StateProviderFactory + ChainSpecProvider<ChainSpec = OpChainSpec> + BlockReaderIdExt,
    {
        let ExecutedPayload {
            info,
            withdrawals_root,
        } = match self.execute(&mut state, &ctx)? {
            BuildOutcomeKind::Better { payload } | BuildOutcomeKind::Freeze(payload) => payload,
            BuildOutcomeKind::Cancelled => return Ok(BuildOutcomeKind::Cancelled),
            BuildOutcomeKind::Aborted { fees } => return Ok(BuildOutcomeKind::Aborted { fees }),
        };

        let block_number = ctx.block_number();
        let execution_outcome = ExecutionOutcome::new(
            state.take_bundle(),
            info.receipts.into(),
            block_number,
            Vec::new(),
        );
        let receipts_root = execution_outcome
            .generic_receipts_root_slow(block_number, |receipts| {
                calculate_receipt_root_no_memo_optimism(
                    receipts,
                    &ctx.inner.chain_spec,
                    ctx.attributes().timestamp(),
                )
            })
            .expect("Number is in range");
        let logs_bloom = execution_outcome
            .block_logs_bloom(block_number)
            .expect("Number is in range");

        // // calculate the state root
        let state_provider = state.database.as_ref();
        let hashed_state = state_provider.hashed_post_state(execution_outcome.state());
        let (state_root, trie_output) = {
            state_provider
                .state_root_with_updates(hashed_state.clone())
                .inspect_err(|err| {
                    warn!(target: "payload_builder",
                    parent_header=%ctx.parent().hash(),
                        %err,
                        "failed to calculate state root for payload"
                    );
                })?
        };

        // create the block header
        let transactions_root = proofs::calculate_transaction_root(&info.executed_transactions);

        // OP doesn't support blobs/EIP-4844.
        // https://specs.optimism.io/protocol/exec-engine.html#ecotone-disable-blob-transactions
        // Need [Some] or [None] based on hardfork to match block hash.
        let (excess_blob_gas, blob_gas_used) = ctx.blob_fields();
        let extra_data = ctx.extra_data()?;

        let header = Header {
            parent_hash: ctx.parent().hash(),
            ommers_hash: EMPTY_OMMER_ROOT_HASH,
            beneficiary: ctx.inner.evm_env.block_env.coinbase,
            state_root,
            transactions_root,
            receipts_root,
            withdrawals_root,
            logs_bloom,
            timestamp: ctx.attributes().payload_attributes.timestamp,
            mix_hash: ctx.attributes().payload_attributes.prev_randao,
            nonce: BEACON_NONCE.into(),
            base_fee_per_gas: Some(ctx.base_fee()),
            number: ctx.parent().number + 1,
            gas_limit: ctx.block_gas_limit(),
            difficulty: U256::ZERO,
            gas_used: info.cumulative_gas_used,
            extra_data,
            parent_beacon_block_root: ctx.attributes().payload_attributes.parent_beacon_block_root,
            blob_gas_used,
            excess_blob_gas,
            requests_hash: None,
        };

        // seal the block
        let block = Block {
            header,
            body: BlockBody {
                transactions: info.executed_transactions,
                ommers: vec![],
                withdrawals: ctx.withdrawals().cloned(),
            },
        };

        let sealed_block = Arc::new(block.seal_slow());
        debug!(target: "payload_builder", id=%ctx.attributes().payload_id(), sealed_block_header = ?sealed_block.header(), "sealed built block");

        // create the executed block data
        let executed: ExecutedBlock<OpPrimitives> = ExecutedBlock {
            recovered_block: Arc::new(RecoveredBlock::new_sealed(
                sealed_block.as_ref().clone(),
                info.executed_senders,
            )),
            execution_output: Arc::new(execution_outcome),
            hashed_state: Arc::new(hashed_state),
            trie: Arc::new(trie_output),
        };

        let no_tx_pool = ctx.attributes().no_tx_pool;

        let payload = OpBuiltPayload::new(
            ctx.payload_id(),
            sealed_block,
            info.total_fees,
            ctx.inner.chain_spec.clone(),
            ctx.inner.config.attributes,
            Some(executed),
        );

        if no_tx_pool {
            // if `no_tx_pool` is set only transactions from the payload attributes will be included
            // in the payload. In other words, the payload is deterministic and we can
            // freeze it once we've successfully built it.
            Ok(BuildOutcomeKind::Freeze(payload))
        } else {
            Ok(BuildOutcomeKind::Better { payload })
        }
    }

    /// Builds the payload and returns its [`ExecutionWitness`] based on the state after execution.
    pub fn witness<EvmConfig, DB, P, Client>(
        self,
        state: &mut State<DB>,
        ctx: &WorldChainPayloadBuilderCtx<EvmConfig, Client>,
    ) -> Result<ExecutionWitness, PayloadBuilderError>
    where
        EvmConfig: ConfigureEvm<Header = Header, Transaction = OpTransactionSigned>,
        DB: Database<Error = ProviderError> + AsRef<P>,
        P: StateProofProvider,
        Client:
            StateProviderFactory + ChainSpecProvider<ChainSpec = OpChainSpec> + BlockReaderIdExt,
    {
        let _ = self.execute(state, ctx)?;
        let ExecutionWitnessRecord {
            hashed_state,
            codes,
            keys,
        } = ExecutionWitnessRecord::from_executed_state(state);
        let state = state
            .database
            .as_ref()
            .witness(Default::default(), hashed_state)?;
        Ok(ExecutionWitness {
            state: state.into_iter().collect(),
            codes,
            keys,
        })
    }
}

/// Container type that holds all necessities to build a new payload.
#[derive(Debug)]
pub struct WorldChainPayloadBuilderCtx<EvmConfig, Client> {
    pub inner: OpPayloadBuilderCtx<EvmConfig>,
    pub verified_blockspace_capacity: u8,
    pub client: Client,
}

impl<EvmConfig, Client> WorldChainPayloadBuilderCtx<EvmConfig, Client> {
    /// Returns the parent block the payload will be build on.
    pub fn parent(&self) -> &SealedHeader {
        self.inner.parent()
    }

    /// Returns the state provider client.
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Returns the builder attributes.
    pub const fn attributes(&self) -> &OpPayloadBuilderAttributes {
        self.inner.attributes()
    }

    /// Returns the withdrawals if shanghai is active.
    pub fn withdrawals(&self) -> Option<&Withdrawals> {
        self.inner.withdrawals()
    }

    /// Returns the block gas limit to target.
    pub fn block_gas_limit(&self) -> u64 {
        self.inner.block_gas_limit()
    }

    /// Returns the block number for the block.
    pub fn block_number(&self) -> u64 {
        self.inner.block_number()
    }

    /// Returns the current base fee
    pub fn base_fee(&self) -> u64 {
        self.inner.base_fee()
    }

    /// Returns the current blob gas price.
    pub fn get_blob_gasprice(&self) -> Option<u64> {
        self.inner.get_blob_gasprice()
    }

    /// Returns the blob fields for the header.
    ///
    /// This will always return `Some(0)` after ecotone.
    pub fn blob_fields(&self) -> (Option<u64>, Option<u64>) {
        self.inner.blob_fields()
    }

    /// Returns the extra data for the block.
    ///
    /// After holocene this extracts the extradata from the paylpad
    pub fn extra_data(&self) -> Result<Bytes, PayloadBuilderError> {
        self.inner.extra_data()
    }

    /// Returns the current fee settings for transactions from the mempool
    // TODO: PBH
    pub fn best_transaction_attributes(&self) -> BestTransactionsAttributes {
        BestTransactionsAttributes::new(self.base_fee(), self.get_blob_gasprice())
    }

    /// Returns the unique id for this payload job.
    pub fn payload_id(&self) -> PayloadId {
        self.inner.payload_id()
    }

    /// Returns true if regolith is active for the payload.
    pub fn is_regolith_active(&self) -> bool {
        self.inner.is_regolith_active()
    }

    /// Returns true if ecotone is active for the payload.
    pub fn is_ecotone_active(&self) -> bool {
        self.inner.is_ecotone_active()
    }

    /// Returns true if canyon is active for the payload.
    pub fn is_canyon_active(&self) -> bool {
        self.inner.is_canyon_active()
    }

    /// Returns true if holocene is active for the payload.
    pub fn is_holocene_active(&self) -> bool {
        self.inner.is_holocene_active()
    }

    /// Returns true if the fees are higher than the previous payload.
    pub fn is_better_payload(&self, total_fees: U256) -> bool {
        is_better_payload(self.inner.best_payload.as_ref(), total_fees)
    }

    /// Commits the withdrawals from the payload attributes to the state.
    pub fn commit_withdrawals<DB>(&self, db: &mut State<DB>) -> Result<Option<B256>, ProviderError>
    where
        DB: Database<Error = ProviderError>,
    {
        self.inner.commit_withdrawals(db)
    }

    /// Ensure that the create2deployer is force-deployed at the canyon transition. Optimism
    /// blocks will always have at least a single transaction in them (the L1 info transaction),
    /// so we can safely assume that this will always be triggered upon the transition and that
    /// the above check for empty blocks will never be hit on OP chains.
    pub fn ensure_create2_deployer<DB>(&self, db: &mut State<DB>) -> Result<(), PayloadBuilderError>
    where
        DB: Database,
        DB::Error: Display,
    {
        self.inner.ensure_create2_deployer(db)
    }
}

impl<EvmConfig, Client> WorldChainPayloadBuilderCtx<EvmConfig, Client>
where
    EvmConfig: ConfigureEvm<Header = Header, Transaction = OpTransactionSigned>,
    Client: StateProviderFactory + ChainSpecProvider<ChainSpec = OpChainSpec> + BlockReaderIdExt,
{
    /// apply eip-4788 pre block contract call
    pub fn apply_pre_beacon_root_contract_call<DB>(
        &self,
        db: &mut DB,
    ) -> Result<(), PayloadBuilderError>
    where
        DB: Database + DatabaseCommit,
        DB::Error: Display,
    {
        self.inner.apply_pre_beacon_root_contract_call(db)
    }

    /// Executes all sequencer transactions that are included in the payload attributes.
    pub fn execute_sequencer_transactions<DB>(
        &self,
        db: &mut State<DB>,
    ) -> Result<ExecutionInfo, PayloadBuilderError>
    where
        DB: Database<Error = ProviderError>,
    {
        self.inner.execute_sequencer_transactions(db)
    }

    /// Executes the given best transactions and updates the execution info.
    ///
    /// Returns `Ok(Some(())` if the job was cancelled.
    pub fn execute_best_transactions<DB, Pool>(
        &self,
        info: &mut ExecutionInfo,
        db: &mut State<DB>,
        pool: &Pool,
        mut best_txs: Box<
            dyn BestTransactions<
                Item = Arc<ValidPoolTransaction<<Pool as TransactionPool>::Transaction>>,
            >,
        >,
    ) -> Result<Option<()>, PayloadBuilderError>
    where
        DB: Database<Error = ProviderError>,
        Pool: TransactionPool<
            Transaction: WorldChainPoolTransaction<Consensus = OpTransactionSigned>,
        >,
    {
        let block_gas_limit = self.block_gas_limit();
        let block_da_limit = self.inner.da_config.max_da_block_size();
        let tx_da_limit = self.inner.da_config.max_da_tx_size();
        let base_fee = self.base_fee();

        let mut evm = self.inner.evm_config.evm_with_env_and_inspector(
            &mut *db,
            self.inner.evm_env.clone(),
            PBHCallTracer::new(),
        );

        let mut invalid_txs = vec![];
        let verified_gas_limit = (self.verified_blockspace_capacity as u64 * block_gas_limit) / 100;
        while let Some(tx) = best_txs.next() {
            let pooled_tx = &tx.transaction;
            let consensus_tx = tx.to_consensus();
            if info.is_tx_over_limits(
                &consensus_tx.tx(),
                block_gas_limit,
                tx_da_limit,
                block_da_limit,
            ) {
                // we can't fit this transaction into the block, so we need to mark it as
                // invalid which also removes all dependent transaction from
                // the iterator before we can continue
                best_txs.mark_invalid(
                    &tx,
                    InvalidPoolTransactionError::ExceedsGasLimit(
                        tx_da_limit.unwrap_or_default(),
                        block_da_limit.unwrap_or_default(),
                    ),
                );
                continue;
            }
            if let Some(conditional_options) = pooled_tx.conditional_options() {
                if validate_conditional_options(conditional_options, &self.client).is_err() {
                    best_txs.mark_invalid(
                        &tx,
                        InvalidPoolTransactionError::Other(Box::new(
                            WorldChainPoolTransactionError::ConditionalValidationFailed(*tx.hash()),
                        )),
                    );
                    invalid_txs.push(*tx.hash());
                    continue;
                }
            }

            // If the transaction is verified, check if it can be added within the verified gas limit
            if tx.transaction.valid_pbh()
                && info.cumulative_gas_used + tx.gas_limit() > verified_gas_limit
            {
                best_txs.mark_invalid(&tx, InvalidPoolTransactionError::Underpriced);
                continue;
            }

            // ensure we still have capacity for this transaction
            if info.cumulative_gas_used + tx.gas_limit() > block_gas_limit {
                // we can't fit this transaction into the block, so we need to mark it as
                // invalid which also removes all dependent transaction from
                // the iterator before we can continue
                best_txs.mark_invalid(&tx, InvalidPoolTransactionError::Underpriced);
                continue;
            }

            // A sequencer's block should never contain blob or deposit transactions from the pool.
            if tx.is_eip4844() || tx.tx_type() == OpTxType::Deposit as u8 {
                best_txs.mark_invalid(
                    &tx,
                    InvalidPoolTransactionError::Consensus(
                        InvalidTransactionError::TxTypeNotSupported,
                    ),
                );
                continue;
            }

            // check if the job was cancelled, if so we can exit early
            if self.inner.cancel.is_cancelled() {
                return Ok(Some(()));
            }

            // Configure the environment for the tx.
            let tx_env = self
                .inner
                .evm_config
                .tx_env(consensus_tx.tx(), consensus_tx.signer());

            let ResultAndState { result, state } = match evm.transact(tx_env) {
                Ok(res) => res,
                Err(err) => {
                    match err {
                        EVMError::Transaction(err) => {
                            if matches!(err, InvalidTransaction::NonceTooLow { .. }) {
                                // if the nonce is too low, we can skip this transaction
                                trace!(target: "payload_builder", %err, ?tx, "skipping nonce too low transaction");
                            } else {
                                // if the transaction is invalid, we can skip it and all of its
                                // descendants
                                trace!(target: "payload_builder", %err, ?tx, "skipping invalid transaction and its descendants");
                                best_txs.mark_invalid(
                                    &tx,
                                    InvalidPoolTransactionError::Other(Box::new(
                                        WorldChainPoolTransactionError::from(err),
                                    )),
                                );
                            }

                            continue;
                        }
                        err => {
                            // this is an error that we should treat as fatal for this attempt
                            return Err(PayloadBuilderError::EvmExecutionError(err));
                        }
                    }
                }
            };

            // commit changes
            evm.db_mut().commit(state);

            let gas_used = result.gas_used();

            // add gas used by the transaction to cumulative gas used, before creating the
            // receipt
            info.cumulative_gas_used += gas_used;
            info.cumulative_da_bytes_used += consensus_tx.length() as u64;

            let receipt = alloy_consensus::Receipt {
                status: Eip658Value::Eip658(result.is_success()),
                cumulative_gas_used: info.cumulative_gas_used,
                logs: result.into_logs().into_iter().collect(),
            };

            // Push transaction changeset and calculate header bloom filter for receipt.
            info.receipts.push(match tx.tx_type() {
                0 => OpReceipt::Legacy(receipt),
                1 => OpReceipt::Eip2930(receipt),
                2 => OpReceipt::Eip1559(receipt),
                4 => OpReceipt::Eip7702(receipt),
                126 => OpReceipt::Deposit(OpDepositReceipt {
                    inner: receipt,
                    deposit_nonce: None,
                    deposit_receipt_version: None,
                }),
                _ => unreachable!(),
            });

            // update add to total fees
            let miner_fee = tx
                .effective_tip_per_gas(base_fee)
                .expect("fee is always valid; execution succeeded");
            info.total_fees += U256::from(miner_fee) * U256::from(gas_used);

            // append sender and transaction to the respective lists
            info.executed_senders.push(consensus_tx.signer());
            info.executed_transactions.push(consensus_tx.into_tx());
        }

        if !invalid_txs.is_empty() {
            pool.remove_transactions(invalid_txs);
        }

        Ok(None)
    }
}
