# Description

A script to send ETH from an address to another without requiring yet another KYC or account creation or connection to a third party.

# Requirements

[Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html)

# Usage

`cargo run`

Then fill in the fields and wait for the transaction to happen.

# Known issues

- The estimated conversion to dollars is hardcoded so it can be off by quite a large amount by the time you use this script

- The tip is hardcoded (it is set to 20% of the base fee) you'll have to edit it manually it you think it is too high (or too low)

- There is no option to "empty" an account so you'll have to do your calculations by hand, with the risk of either having your transaction refused because you don't have enough funds for the transaction + the fees, or most likely having the transaction come through but with a small amount (less than 0.01$ ?) left on the address of the sender.

- The node you used ignored your transaction or gave it a low priority, so the script seems to be pending forever. You can kill the script and try again with another node, but make sure the `nonce` is the same to garantee that the fund will only be sent once. You can check on an eth scanner online if your transaction went through.
