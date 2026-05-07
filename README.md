# Third-party durable nonce advance example

This repository is a minimal LiteSVM reproduction for a withheld durable nonce
transaction using a v1 message.

The test shows this flow:

1. The attacker creates a durable nonce account where the attacker is the nonce
   authority.
2. The victim has a USDC token account owned by the SPL Token program.
3. The attacker builds a v1 transaction message whose first instruction advances
   the attacker's durable nonce.
4. The same transaction also contains a victim-signed SPL Token `SetAuthority`
   instruction that changes the victim's USDC token account owner to the
   attacker.
5. The attacker withholds the fully signed transaction, then the test warps the
   LiteSVM slot and expires the latest ordinary blockhash.
6. The attacker submits the withheld transaction. Because it is backed by the
   durable nonce, it still executes, and the token account owner becomes the
   attacker.

Run it with:

```sh
cargo test
```
