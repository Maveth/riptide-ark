# Riptide server branch

`riptide` is this server built on Paperclip `main` at `f33bd70`. It is a local branch. It has not been pushed.

## Kept from Paperclip

- Board registration is bound to the server funding output (`c27375b`).
- Ordinary transfers can use the lower recovery allocation (`f33bd70`): a 330 sat anchor and a 198 sat miner fee, when economical transfers are enabled.
- The release-policy doc no longer points at the experimental package.

## Added here

- Lightning payments under 1,000 sats use the tab. A payment of 1,000 sats or more stays a coin.
- One `GetLightningTabs` call returns every key's balance and opt-out flag.
- A route that cannot be priced is held at 75 sats. After the payment, the tab keeps the route cost plus 1 sat and returns the unused hold.
- A withdrawal under 1,000 sats is refused. The user tops up 1,000 sats, then withdraws the whole tab. There is no withdrawal fee.
- Profile 2 still means a wallet may connect. `zero_fee_board` selects the zero-fee board. An older wallet that leaves the flag unset still gets the 1,000 sat anchor and 1,000 sat miner fee.
- Ark sends are accepted on the zero-fee shape, the older 1,000 sat shape, the older 330 plus 1,000 sat shape, and Paperclip's 330 plus 198 sat shape.
- Rounds on this server stay zero-fee. An older wallet can board and pay here. It cannot join one of these rounds.

## Left out

- `lib/src/arkoor/combine.rs` is unfinished and is not part of the branch.
