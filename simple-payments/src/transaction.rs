use crate::account::{AccountId, AccountPublicKey, AccountSecretKey};
use crate::ledger::{self, Amount};
use crate::signature::{
    schnorr::{self, Schnorr},
    SignatureScheme,
};
use ark_ed_on_bls12_381::EdwardsProjective;
use ark_std::rand::Rng;

/// Transaction transferring some amount from one account to another.
#[derive(Clone, Debug)]
pub struct Transaction {
    /// The account information of the sender.
    pub sender: AccountId,
    /// The account information of the recipient.
    pub recipient: AccountId,
    /// The amount being transferred from the sender to the receiver.
    pub amount: Amount,
    /// The spend authorization is a signature over the sender, the recipient,
    /// and the amount.
    pub signature: schnorr::Signature<EdwardsProjective>,
    pub recipient_signature: Option<schnorr::Signature<EdwardsProjective>>,
}

impl Transaction {
    /// The threshold for a large amount.
    const LARGE_AMOUNT_THRESHOLD: u64 = 1000;


    /// Verify just the signature in the transaction.
    fn verify_signature(
        &self,
        pp: &schnorr::Parameters<EdwardsProjective>,
        pub_key: &AccountPublicKey,
    ) -> bool {
        // The authorized message consists of
        // (SenderAccId || SenderPubKey || RecipientAccId || RecipientPubKey || Amount)
        let mut message = self.sender.to_bytes_le();
        message.extend(self.recipient.to_bytes_le());
        message.extend(self.amount.to_bytes_le());
        Schnorr::verify(pp, pub_key, &message, &self.signature).unwrap()
    }

    /// Check if the transaction requires recipient confirmation.
    fn requires_recipient_confirmation(&self) -> bool {
        self.amount.0 > Self::LARGE_AMOUNT_THRESHOLD
    }

    /// Validate the recipient's confirmation for large transactions.
    fn validate_recipient_confirmation(&self, parameters: &ledger::Parameters, state: &ledger::State) -> bool {
        if self.requires_recipient_confirmation() {
            if let Some(recipient_acc_info) = state.id_to_account_info.get(&self.recipient) {
                // Verify the recipient's confirmation signature
                if let Some(recipient_signature) = self.recipient_signature.clone() {
                    let mut message = self.sender.to_bytes_le();
                    message.extend(self.recipient.to_bytes_le());
                    message.extend(self.amount.to_bytes_le());
                    Schnorr::verify(
                        &parameters.sig_params,
                        &recipient_acc_info.public_key,
                        &message,
                        &recipient_signature,
                    )
                    .unwrap()
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            true
        }
    }

    /// Check that the transaction is valid for the given ledger state. This checks
    /// the following conditions:
    /// 1. Verify that the signature is valid with respect to the public key
    /// corresponding to `self.sender`.
    /// 2. Verify that the sender's account has sufficient balance to finance
    /// the transaction.
    /// 3. Verify that the recipient's account exists.
    pub fn validate(&self, parameters: &ledger::Parameters, state: &ledger::State) -> bool {
        // Lookup public key corresponding to sender ID
        if let Some(sender_acc_info) = state.id_to_account_info.get(&self.sender) {
            let mut result = true;
            // Check that the account_info exists in the Merkle tree.
            result &= {
                let path = state
                    .account_merkle_tree
                    .generate_proof(self.sender.0 as usize)
                    .expect("path should exist");
                path.verify(
                    &parameters.leaf_crh_params,
                    &parameters.two_to_one_crh_params,
                    &state.account_merkle_tree.root(),
                    &sender_acc_info.to_bytes_le(),
                )
                .unwrap()
            };
            // Verify the signature against the sender pubkey.
            result &= self.verify_signature(&parameters.sig_params, &sender_acc_info.public_key);
            // assert!(result, "signature verification failed");
            // Verify the amount is available in the sender account.
            result &= self.amount <= sender_acc_info.balance;
            // Verify that recipient account exists.
            result &= state.id_to_account_info.get(&self.recipient).is_some();
            // Validate recipient confirmation for large transactions.
            result &= self.validate_recipient_confirmation(parameters, state);
            result
        } else {
            false
        }
    }

    /// Create a (possibly invalid) transaction.
    pub fn create<R: Rng>(
        parameters: &ledger::Parameters,
        sender: AccountId,
        recipient: AccountId,
        amount: Amount,
        sender_sk: &AccountSecretKey,
        recipient_sk: Option<&AccountSecretKey>,
        rng: &mut R,
    ) -> Self {
        // The authorized message consists of (SenderAccId || RecipientAccId || Amount)
        let mut message = sender.to_bytes_le();
        message.extend(recipient.to_bytes_le());
        message.extend(amount.to_bytes_le());
        let signature = Schnorr::sign(&parameters.sig_params, sender_sk, &message, rng).unwrap();
        let recipient_signature = if amount.0 > Self::LARGE_AMOUNT_THRESHOLD {
            if let Some(recipient_sk) = recipient_sk {
                let mut recipient_message = sender.to_bytes_le();
                recipient_message.extend(recipient.to_bytes_le());
                recipient_message.extend(amount.to_bytes_le());
                let recipient_signature = Schnorr::sign(
                    &parameters.sig_params,
                    recipient_sk,
                    &recipient_message,
                    rng,
                )
                .unwrap();
                Some(recipient_signature)
            } else {
                None
            }
        } else {
            None
        };

        Self {
            sender,
            recipient,
            amount,
            signature,
            recipient_signature
        }
    }
}

// Ideas to make exercises more interesting/complex:
// 1. Add fees
// 2. Add recipient confirmation requirement if tx amount is too large.
// 3. Add authority confirmation if tx amount is too large.
// 4. Create account if it doesn't exist.
// 5. Add idea for compressing state transitions with repeated senders and recipients.
