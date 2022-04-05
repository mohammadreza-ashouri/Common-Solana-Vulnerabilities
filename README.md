# Common-Solana-Vulnerabilities


---

### 3 Most Common Vulnerabilities in Solana and Anchor Contracts

Hey everyone!
This is Mo, and I am the CEO of ByteScan.net, a team of security researchers who have spent the past ~24 months inspecting the internals of the Solana blockchain. 
Solana is such a rapidly expanding ecosystem, and throughout our research, we found and reported several vulnerabilities in various Solana-based DeFi projects, eventually helping to secure the projects against attackers.
Since 2020, we've been working with developers from a range of projects building on Solana to assist them in securing their contracts. We've audited dozens of contracts, using our unique experience with Solana to uncover numerous exploitable bugs.
This article aims to raise attention around the three most common vulnerabilities in Solana contracts (including Anchor programs) that we keep finding during our audits.
We'll keep the vulnerability descriptions short and concise and provide a simplified example as well. We hope developers and other auditors will be able to use it. If you like to learn more about the ByteScan.net team, please check out https://bytescan.net.

#### 1- Missing Ownership Control

Your contract must only trust accounts owned by itself. That means, as a Solana developer, you must always review the AccountInfo::owner field of accounts in your code. Note that these are not supposed to be wholly user-controlled. Therefore, you may create a helper function that takes an untrusted AccountInfo, inspects the owner, and returns an object of a different, trusted type.


Consider the following code representing a vulnerable function called "withdraw_funds". The developer intended that this is an admin-only instruction to withdraw funds from the contract vault:


```
fn withdraw_funds(program_id: &Pubkey, accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let vault = next_account_info(account_iter)?;
    let admin = next_account_info(account_iter)?;
    let config = ConfigAccount::unpack(next_account_info(account_iter)?)?;
    let vault_authority = next_account_info(account_iter)?;
    
    
    if config.admin != admin.pubkey() {
        return Err(ProgramError::InvalidAdminAccount);
    }
    
    // ...
    // Transfer funds from vault to admin using vault_authority
    // ...
    
    Ok(())
}
```


#### 2- Missing Signer Check

If an instruction should only be open to a fixed set of entities, you must control that the right entity has signed the call by inspecting the AccountInfo::is_signer field. 
Note that virtually any smart contract has instructions that are limited to be only called by specific entities, for example, admin-only instructions like locking the contract or user-specific instructions that alter the state of a user's account. Although it seems pretty obvious to verify that the respective entity has signed the related transaction, these checks are usually forgotten.

A vulnerable example:

```
fn admin_update(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let config = ConfigAccount::unpack(next_account_info(account_iter)?)?;
    let admin = next_account_info(account_iter)?;
    let admin_new = next_account_info(account_iter)?;

    // ...
    // Validate the config account...
    // ...
    
    if admin.pubkey() != config.admin {
        return Err(ProgramError::InvalidAdminAccount);
    }
    
    config.admin = admin_new.pubkey();
    
    Ok(())
}
```


#### 3- Arithmetic underflow & overflow

In smart contracts, overflow/underflows are quite common because blockchain applications often compute math over financial data.
Both Solana smart contracts and Solana's core runtime are written in Rust, and there have been several public reports about arithmetic overflows/underflows in Solana core runtime.
It may be a misconception that Rust is memory-safe, so it is free of arithmetic overflow/underflows for many developers, but this is only true in debug mode. However, when developers compile their contracts in release mode with the - release flag, Rust does not check for integer overflow that causes panics. Rather, if overflow occurs, Rust performs two's complement wrapping. In brief, values greater than the maximum value the type can hold "wrap around" to the minimum of the type's values. The program won't panic, whereas the variable will have a value that probably isn't what you expected.
Note that you're compiling your contracts in release mode by using the Solana BPF toolchain ($ cargo build-bpf).

A vulnerable example:

```
let X: u32 = 1000; 

fn token_withdraw(program_id: &Pubkey, accounts: &[AccountInfo], amount: u32) -> ProgramResult {

    // ...
    // deserialize & validate user and vault accounts
    // ...
    
    if amount + X > vault.user_balance[user_id] {
        return Err(ProgramError::AttemptToWithdrawTooMuch);
    }
    
    // ...
    // Transfer `amount` many tokens from vault to user-controlled account ...
    // ...
    
    Ok(())
}
```
