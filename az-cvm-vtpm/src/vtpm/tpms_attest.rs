// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Pure-Rust parsing of the TPM 2.0 `TPMS_ATTEST` structure.
//!
//! Quote verification only needs two fields of a quote-type attestation
//! structure: `extraData` (the caller-provided nonce) and the attested
//! `pcrDigest`. `TPMS_ATTEST` is a flat, big-endian structure frozen by
//! the TPM 2.0 Library Specification (Part 2: Structures, section 10.12),
//! so it can be parsed here without the tss-esapi FFI stack. This keeps
//! quote verification free of native TPM library dependencies and
//! portable to platforms without tpm2-tss.

use thiserror::Error;

/// TPM_GENERATED_VALUE, the magic constant leading every TPMS_ATTEST
/// (TPM 2.0 spec Part 2, section 6.2).
const TPM_GENERATED_VALUE: u32 = 0xff54_4347;

/// TPM_ST_ATTEST_QUOTE, the tag of quote-type attestation structures
/// (TPM 2.0 spec Part 2, section 6.9).
const TPM_ST_ATTEST_QUOTE: u16 = 0x8018;

/// Maximum number of TPMS_PCR_SELECTION entries accepted in a
/// TPML_PCR_SELECTION. The spec bounds the list by the number of hash
/// algorithms the TPM implements (TPM 2.0 spec Part 2, section 10.9.7);
/// 16 is far above any real TPM and merely bounds work on hostile input.
const MAX_PCR_SELECTIONS: u32 = 16;

#[derive(Error, Debug)]
pub enum AttestError {
    #[error("buffer too short for TPMS_ATTEST field")]
    Truncated,
    #[error("TPMS_ATTEST magic is not TPM_GENERATED_VALUE")]
    Magic,
    #[error("TPMS_ATTEST is not a quote")]
    NotAQuote,
    #[error("TPML_PCR_SELECTION count is implausibly large")]
    PcrSelectionCount,
    #[error("trailing bytes after TPMS_ATTEST")]
    TrailingData,
}

/// The quote-relevant fields of a marshalled `TPMS_ATTEST` structure.
#[derive(Debug)]
pub struct TpmsAttest {
    extra_data: Vec<u8>,
    // Read by quote verification only (the `verifier` feature).
    #[cfg_attr(not(feature = "verifier"), allow(dead_code))]
    pcr_digest: Vec<u8>,
}

impl TpmsAttest {
    /// Parse a marshalled TPMS_ATTEST, accepting only quote-type
    /// attestation structures (TPM_ST_ATTEST_QUOTE).
    pub fn parse(bytes: &[u8]) -> Result<Self, AttestError> {
        let mut reader = Reader { bytes, offset: 0 };
        if reader.read_u32()? != TPM_GENERATED_VALUE {
            return Err(AttestError::Magic);
        }
        if reader.read_u16()? != TPM_ST_ATTEST_QUOTE {
            return Err(AttestError::NotAQuote);
        }
        // qualifiedSigner: TPM2B_NAME
        reader.read_tpm2b()?;
        // extraData: TPM2B_DATA
        let extra_data = reader.read_tpm2b()?.to_vec();
        // clockInfo: TPMS_CLOCK_INFO (clock, resetCount, restartCount, safe)
        reader.skip(8 + 4 + 4 + 1)?;
        // firmwareVersion: UINT64
        reader.skip(8)?;
        // attested.quote: TPMS_QUOTE_INFO, starting with the pcrSelect
        // list (TPML_PCR_SELECTION)
        let selection_count = reader.read_u32()?;
        if selection_count > MAX_PCR_SELECTIONS {
            return Err(AttestError::PcrSelectionCount);
        }
        for _ in 0..selection_count {
            // TPMS_PCR_SELECTION: hash algorithm, sizeofSelect, pcrSelect
            reader.skip(2)?;
            let size_of_select = reader.read_u8()? as usize;
            reader.skip(size_of_select)?;
        }
        // attested.quote.pcrDigest: TPM2B_DIGEST
        let pcr_digest = reader.read_tpm2b()?.to_vec();
        if reader.offset != bytes.len() {
            return Err(AttestError::TrailingData);
        }
        Ok(Self {
            extra_data,
            pcr_digest,
        })
    }

    /// The `extraData` field: caller-provided qualifying data (the nonce).
    pub fn extra_data(&self) -> &[u8] {
        &self.extra_data
    }

    /// The attested `pcrDigest`: digest of the selected PCR values.
    #[cfg_attr(not(feature = "verifier"), allow(dead_code))]
    pub fn pcr_digest(&self) -> &[u8] {
        &self.pcr_digest
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], AttestError> {
        let end = self.offset.checked_add(len).ok_or(AttestError::Truncated)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(AttestError::Truncated)?;
        self.offset = end;
        Ok(bytes)
    }

    fn skip(&mut self, len: usize) -> Result<(), AttestError> {
        self.take(len).map(|_| ())
    }

    fn read_u8(&mut self) -> Result<u8, AttestError> {
        Ok(self.take(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, AttestError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn read_u32(&mut self) -> Result<u32, AttestError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    /// Read a size-prefixed TPM2B buffer (16-bit big-endian size followed
    /// by that many bytes).
    fn read_tpm2b(&mut self) -> Result<&'a [u8], AttestError> {
        let size = self.read_u16()? as usize;
        self.take(size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal marshalled quote-type TPMS_ATTEST.
    fn build_attest(magic: u32, attest_type: u16, extra_data: &[u8], pcr_digest: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&magic.to_be_bytes());
        bytes.extend_from_slice(&attest_type.to_be_bytes());
        // qualifiedSigner: TPM2B_NAME with a 4-byte name
        bytes.extend_from_slice(&4u16.to_be_bytes());
        bytes.extend_from_slice(&[0xaa; 4]);
        // extraData: TPM2B_DATA
        bytes.extend_from_slice(&(extra_data.len() as u16).to_be_bytes());
        bytes.extend_from_slice(extra_data);
        // clockInfo + firmwareVersion
        bytes.extend_from_slice(&[0; 8 + 4 + 4 + 1]);
        bytes.extend_from_slice(&[0; 8]);
        // TPML_PCR_SELECTION: one SHA-256 selection of PCRs 0-23
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&0x000bu16.to_be_bytes());
        bytes.push(3);
        bytes.extend_from_slice(&[0xff, 0xff, 0xff]);
        // pcrDigest: TPM2B_DIGEST
        bytes.extend_from_slice(&(pcr_digest.len() as u16).to_be_bytes());
        bytes.extend_from_slice(pcr_digest);
        bytes
    }

    #[test]
    fn parses_quote_fields() {
        let extra_data = b"challenge";
        let pcr_digest = [0x42; 32];
        let bytes = build_attest(
            TPM_GENERATED_VALUE,
            TPM_ST_ATTEST_QUOTE,
            extra_data,
            &pcr_digest,
        );
        let attest = TpmsAttest::parse(&bytes).unwrap();
        assert_eq!(attest.extra_data(), extra_data);
        assert_eq!(attest.pcr_digest(), pcr_digest);
    }

    #[test]
    fn rejects_bad_magic() {
        let bytes = build_attest(0xdeadbeef, TPM_ST_ATTEST_QUOTE, b"x", &[0; 32]);
        assert!(matches!(TpmsAttest::parse(&bytes), Err(AttestError::Magic)));
    }

    #[test]
    fn rejects_non_quote_attestation() {
        // TPM_ST_ATTEST_CERTIFY
        let bytes = build_attest(TPM_GENERATED_VALUE, 0x8017, b"x", &[0; 32]);
        assert!(matches!(
            TpmsAttest::parse(&bytes),
            Err(AttestError::NotAQuote)
        ));
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut bytes = build_attest(TPM_GENERATED_VALUE, TPM_ST_ATTEST_QUOTE, b"x", &[0; 32]);
        bytes.push(0);
        assert!(matches!(
            TpmsAttest::parse(&bytes),
            Err(AttestError::TrailingData)
        ));
    }

    #[test]
    fn rejects_truncation_at_every_length() {
        let bytes = build_attest(TPM_GENERATED_VALUE, TPM_ST_ATTEST_QUOTE, b"x", &[0; 32]);
        for len in 0..bytes.len() {
            assert!(
                matches!(
                    TpmsAttest::parse(&bytes[..len]),
                    Err(AttestError::Truncated)
                ),
                "unexpected result at length {len}"
            );
        }
    }

    #[test]
    fn rejects_implausible_pcr_selection_count() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&TPM_GENERATED_VALUE.to_be_bytes());
        bytes.extend_from_slice(&TPM_ST_ATTEST_QUOTE.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes()); // qualifiedSigner
        bytes.extend_from_slice(&0u16.to_be_bytes()); // extraData
        bytes.extend_from_slice(&[0; 8 + 4 + 4 + 1 + 8]); // clockInfo + firmwareVersion
        bytes.extend_from_slice(&u32::MAX.to_be_bytes()); // pcrSelect count
        assert!(matches!(
            TpmsAttest::parse(&bytes),
            Err(AttestError::PcrSelectionCount)
        ));
    }
}
