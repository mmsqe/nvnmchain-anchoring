//! The contract's `registries` view, which the index is copied from.

use alloy_sol_types::{sol, SolCall};
use anyhow::{Context, Result};

sol! {
    #![sol(all_derives)]

    /// `IAnchoring.Registry`, field for field.
    struct Registry {
        uint64 id;
        string name;
        string description;
        string creator;
        string createdAt;
        string metadata;
    }

    struct PageRequest {
        bytes key;
        uint64 offset;
        uint64 limit;
        bool countTotal;
        bool reverse;
    }

    struct PageResponse {
        bytes nextKey;
        uint64 total;
    }

    function registries(uint64 registryId, PageRequest pagination)
        external
        view
        returns (Registry[] registriesOut, PageResponse paginationOut);
}

/// The most one page holds. The contract clamps a larger limit to this.
const MAX_PAGE: u64 = 200;

/// Calldata for the registries after id `after`, oldest first. The cursor is `after + 1` as eight
/// big-endian bytes, which the contract reads the way `query.CollectionPaginate` did.
pub fn page_after(after: u64) -> Vec<u8> {
    registriesCall {
        registryId: 0,
        pagination: PageRequest {
            key: after.saturating_add(1).to_be_bytes().to_vec().into(),
            offset: 0,
            limit: MAX_PAGE,
            countTotal: false,
            reverse: false,
        },
    }
    .abi_encode()
}

/// One page as the contract returned it, and whether another follows.
pub fn decode_page(returned: &[u8]) -> Result<(Vec<Registry>, bool)> {
    let page = registriesCall::abi_decode_returns(returned).context("decode registries()")?;
    Ok((page.registriesOut, !page.paginationOut.nextKey.is_empty()))
}
